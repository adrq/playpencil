//! Finalizes the components of an assembled `/v1` document: rebuilds the
//! composed components from the wire types, adds a fallback variant to each
//! open tagged union, and marks every object other than a typed map as
//! accepting additional members.

use serde_json::json;
use utoipa::PartialSchema;
use utoipa::openapi::extensions::Extensions;
use utoipa::openapi::schema::{
    AdditionalProperties, ArrayBuilder, ArrayItems, Object, ObjectBuilder, Schema, SchemaType, Type,
};
use utoipa::openapi::{Components, OpenApi, RefOr};

use super::event::{DenyDetails, Destination, Notice, NoticeEvent};
use super::network::NetworkRead;
use super::process::ProcessState;

/// Finalizes the document's components. The result depends only on the wire
/// types, not on the finalized or derived form of these components already
/// present, so applying it again changes nothing.
pub(crate) fn finalize(api: &mut OpenApi) -> Result<(), String> {
    let components = api.components.get_or_insert_with(Components::new);

    let mut notice = one_of(Notice::schema(), "Notice")?;
    add_unknown_tag_fallback(
        &mut notice,
        "Notice",
        "code",
        "Unlisted code.",
        vec![
            ("message", Object::with_type(Type::String).into()),
            ("details", Object::with_type(Type::Object).into()),
        ],
    )?;
    let notice_event = distribute_into_union(NoticeEvent::schema(), notice, "NoticeEvent")?;
    components.schemas.remove("Notice");
    components
        .schemas
        .insert("NoticeEvent".to_string(), notice_event.into());

    let destination = match Destination::schema() {
        RefOr::T(schema) => schema,
        RefOr::Ref(_) => return Err("Destination schema is a reference".to_string()),
    };
    let deny = distribute_into_union(DenyDetails::schema(), destination, "DenyDetails")?;
    components.schemas.remove("Destination");
    components
        .schemas
        .insert("DenyDetails".to_string(), deny.into());

    let mut process_state = one_of(ProcessState::schema(), "ProcessState")?;
    add_unknown_tag_fallback(
        &mut process_state,
        "ProcessState",
        "kind",
        "Unlisted kind.",
        vec![],
    )?;
    components
        .schemas
        .insert("ProcessState".to_string(), process_state.into());

    let mut network_read = one_of(NetworkRead::schema(), "NetworkRead")?;
    add_unknown_tag_fallback(
        &mut network_read,
        "NetworkRead",
        "mode",
        "Unlisted mode.",
        vec![(
            "entries",
            ArrayBuilder::new()
                .items(Object::with_type(Type::String))
                .into(),
        )],
    )?;
    components
        .schemas
        .insert("NetworkRead".to_string(), network_read.into());

    for schema in components.schemas.values_mut() {
        open_objects(schema);
    }
    Ok(())
}

fn one_of(schema: RefOr<Schema>, name: &str) -> Result<Schema, String> {
    match schema {
        RefOr::T(schema @ Schema::OneOf(_)) => Ok(schema),
        _ => Err(format!("{name} schema is not a oneOf")),
    }
}

/// Appends to a tagged `oneOf` a variant whose tag is any value other than the
/// known ones.
fn add_unknown_tag_fallback(
    union: &mut Schema,
    name: &str,
    tag: &str,
    description: &str,
    members: Vec<(&str, RefOr<Schema>)>,
) -> Result<(), String> {
    let Schema::OneOf(one_of) = union else {
        return Err(format!("{name} schema is not a oneOf"));
    };
    let known = one_of
        .items
        .iter()
        .map(|item| {
            known_tag_value(item, tag)
                .ok_or_else(|| format!("{name} variant has no single `{tag}` value"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let tag_schema = ObjectBuilder::new()
        .schema_type(Type::String)
        .extensions(Some(Extensions::from_iter([(
            "not",
            json!({ "enum": known }),
        )])))
        .build();
    let mut fallback = ObjectBuilder::new()
        .schema_type(Type::Object)
        .description(Some(description))
        .property(tag, tag_schema)
        .required(tag);
    for (member, schema) in members {
        fallback = fallback.property(member, schema);
    }
    one_of.items.push(fallback.into());
    Ok(())
}

fn known_tag_value(item: &RefOr<Schema>, tag: &str) -> Option<serde_json::Value> {
    let RefOr::T(Schema::Object(variant)) = item else {
        return None;
    };
    let RefOr::T(Schema::Object(tag_schema)) = variant.properties.get(tag)? else {
        return None;
    };
    match tag_schema.enum_values.as_deref() {
        Some([value]) => Some(value.clone()),
        _ => None,
    }
}

/// Turns `composed`, an `allOf` of a reference to `union` and an inline object,
/// into a union of the same kind whose branches each combine one of the union's
/// branches with that object's members.
fn distribute_into_union(
    composed: RefOr<Schema>,
    union: Schema,
    name: &str,
) -> Result<Schema, String> {
    let RefOr::T(Schema::AllOf(all_of)) = composed else {
        return Err(format!("{name} schema is not an allOf"));
    };
    let envelope = all_of
        .items
        .iter()
        .find_map(|item| match item {
            RefOr::T(Schema::Object(object)) => Some(object.clone()),
            _ => None,
        })
        .ok_or_else(|| format!("{name} schema has no inline object"))?;
    let merge = |branch: &RefOr<Schema>| -> Result<RefOr<Schema>, String> {
        let RefOr::T(Schema::Object(branch)) = branch else {
            return Err(format!("{name}: union branch is not an inline object"));
        };
        let mut merged = branch.clone();
        for (member, schema) in &envelope.properties {
            merged.properties.insert(member.clone(), schema.clone());
        }
        for member in &envelope.required {
            if !merged.required.contains(member) {
                merged.required.push(member.clone());
            }
        }
        Ok(RefOr::T(Schema::Object(merged)))
    };
    match union {
        Schema::OneOf(mut one_of) => {
            one_of.items = one_of.items.iter().map(merge).collect::<Result<_, _>>()?;
            one_of.description = all_of.description;
            Ok(Schema::OneOf(one_of))
        }
        Schema::AnyOf(mut any_of) => {
            any_of.items = any_of.items.iter().map(merge).collect::<Result<_, _>>()?;
            any_of.description = all_of.description;
            Ok(Schema::AnyOf(any_of))
        }
        _ => Err(format!("{name}: composed union is not a oneOf or anyOf")),
    }
}

/// Marks every object schema without an explicit `additionalProperties` as
/// accepting additional members; typed maps keep their value schema.
fn open_objects(schema: &mut RefOr<Schema>) {
    let RefOr::T(schema) = schema else {
        return;
    };
    match schema {
        Schema::Object(object) => {
            let is_object = object.schema_type == SchemaType::Type(Type::Object)
                || !object.properties.is_empty();
            if is_object && object.additional_properties.is_none() {
                object.additional_properties = Some(Box::new(AdditionalProperties::FreeForm(true)));
            }
            for property in object.properties.values_mut() {
                open_objects(property);
            }
            if let Some(additional) = object.additional_properties.as_deref_mut()
                && let AdditionalProperties::RefOr(value) = additional
            {
                open_objects(value);
            }
        }
        Schema::Array(array) => {
            if let ArrayItems::RefOrSchema(items) = &mut array.items {
                open_objects(items);
            }
        }
        Schema::OneOf(one_of) => one_of.items.iter_mut().for_each(open_objects),
        Schema::AnyOf(any_of) => any_of.items.iter_mut().for_each(open_objects),
        Schema::AllOf(all_of) => all_of.items.iter_mut().for_each(open_objects),
        _ => {}
    }
}

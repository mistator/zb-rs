use crate::utils::{as_lit_int, as_path};
use proc_macro2::{Ident, Span, TokenStream};
use quote::{ToTokens, quote};
use std::collections::HashMap;
use syn::parse::{Parse, ParseStream};
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::{Attribute, Expr, ExprTuple, Field, Fields, FieldsNamed, FieldsUnnamed, GenericParam, Generics, ItemStruct, LitInt, Meta, MetaNameValue, Path, PathSegment, Token, Type, TypePath, Visibility};

pub struct ZclAttrParams {
    pub identifier: LitInt,
    pub variant: Option<PathSegment>,
    pub access: Option<Path>,
    pub default: Option<Expr>,
    pub reported: Option<(Expr, Expr, Expr)>,
    pub range: Option<(Expr, Expr)>,
    pub crate_name: Option<PathSegment>
}

impl ZclAttrParams {
    const KEYS: [&'static str; 7] = ["identifier", "variant", "access", "default", "reported", "range", "crate"];
}

impl Parse for ZclAttrParams {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let items = Punctuated::<MetaNameValue, Token![,]>::parse_terminated(input)?;

        let items = items.iter()
            .map(|item| {
                let key = item.path
                    .get_ident()
                    .ok_or(syn::Error::new(item.span(), "invalid key"))?
                    .to_string();
                if !ZclAttrParams::KEYS.contains(&key.as_str()) {
                    return Err(syn::Error::new(item.span(), "invalid key"))
                }
                Ok((key, item.value.clone()))
            })
            .collect::<syn::Result<Vec<(String, Expr)>>>()?;
        let items = HashMap::<String, Expr>::from_iter(items);

        let identifier = items.get("identifier")
            .ok_or(syn::Error::new(input.span(), "missing identifier"))?;
        let identifier = as_lit_int(identifier)?;

        let variant = items.get("variant")
            .map(|item| as_path(item)
                .unwrap()
                .segments
                .last()
                .unwrap()
                .clone()
            );

        let reported = match items.get("reported") {
            None => None,
            Some(Expr::Tuple(ExprTuple { elems, .. })) => {
                if elems.len() != 3 {
                    return Err(syn::Error::new(input.span(), "invalid format for reported attribute"))
                } else {
                    Some((elems[0].clone(), elems[1].clone(), elems[2].clone()))
                }
            }
            _ => {
                return Err(syn::Error::new(input.span(), "invalid format for reported attribute"))
            }
        };

        let range = match items.get("range") {
            None => None,
            Some(Expr::Tuple(ExprTuple { elems, .. })) => {
                if elems.len() != 2 {
                    return Err(syn::Error::new(input.span(), "invalid format for range attribute"))
                } else {
                    Some((elems[0].clone(), elems[1].clone()))
                }
            }
            _ => {
                return Err(syn::Error::new(input.span(), "invalid format for range attribute"))
            }
        };

        let crate_name = items.get("crate")
            .map(|item| as_path(item)
                .unwrap()
                .segments
                .last()
                .unwrap()
                .clone()
            );


        Ok(ZclAttrParams {
            identifier,
            variant,
            access: items.get("access").map(|item| as_path(item).unwrap()),
            default: items.get("default").cloned(),
            reported,
            range,
            crate_name,
        })
    }
}

pub struct ZclAttrStructDef {
    pub attrs: Vec<Attribute>,
    pub vis: Visibility,
    pub ident: Ident,
    pub generics: Generics,
    pub field: Field,
}

impl Parse for ZclAttrStructDef {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let strct = ItemStruct::parse(input)?;
        let field = match strct.fields {
            Fields::Unnamed(FieldsUnnamed { ref unnamed, .. }) => {
                if unnamed.len() != 1 {
                    return Err(syn::Error::new(strct.fields.span(), "invalid struct definition"))
                }
                unnamed.first().unwrap().clone()
            }
            _ => return Err(syn::Error::new(strct.fields.span(), "invalid struct definition"))
        };

        Ok(Self {
            attrs: strct.attrs,
            vis: strct.vis,
            ident: strct.ident,
            generics: strct.generics,
            field
        })
    }
}

pub struct ZclAttr {
    pub params: ZclAttrParams,
    pub struct_def: ZclAttrStructDef,
}

pub fn get_zcl_identifier(variant: String) -> LitInt {
    let id = match variant.as_str() {
        "Null" => 0x00,
        "Data8" => 0x08,
        "Data16" => 0x09,
        "Data24" => 0x0a,
        "Data32" => 0x0b,
        "Data40" => 0x0c,
        "Data48" => 0x0d,
        "Data56" => 0x0e,
        "Data64" => 0x0f,
        "Bool" => 0x10,
        "Bitmap8" => 0x18,
        "Bitmap16" => 0x19,
        "Bitmap24" => 0x1a,
        "Bitmap32" => 0x1b,
        "Bitmap40" => 0x1c,
        "Bitmap48" => 0x1d,
        "Bitmap56" => 0x1e,
        "Bitmap64" => 0x1f,
        "UInt8" => 0x20,
        "UInt16" => 0x21,
        "UInt24" => 0x22,
        "UInt32" => 0x23,
        "UInt40" => 0x24,
        "UInt48" => 0x25,
        "UInt56" => 0x26,
        "UInt64" => 0x27,
        "Int8" => 0x28,
        "Int16" => 0x29,
        "Int24" => 0x2a,
        "Int32" => 0x2b,
        "Int40" => 0x2c,
        "Int48" => 0x2d,
        "Int56" => 0x2e,
        "Int64" => 0x2f,
        "Enum8" => 0x30,
        "Enum16" => 0x31,
        "Float16" => 0x38,
        "Float" => 0x39,
        "Double" => 0x3a,
        "OctetString" => 0x41,
        "String" => 0x42,
        "LongOctetString" => 0x43,
        "LongString" => 0x44,
        "Array" => 0x48,
        "Structure" => 0x4c,
        "Set" => 0x50,
        "Bag" => 0x51,
        "Time" => 0xe0,
        "Date" => 0xe1,
        "Timestamp" => 0xe2,
        "ClusterId" => 0xe8,
        "AttributeId" => 0xe9,
        "BacNetOid" => 0xea,
        "IeeeAddress" => 0xf0,
        "SecurityKey" => 0xf1,
        _ => panic!("invalid ZclVariant")
    };

    LitInt::new(id.to_string().as_str(), variant.span())
}

impl ToTokens for ZclAttr {
    #[allow(non_snake_case)]
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let ZclAttrParams { identifier, variant, access, default, reported, range, crate_name } = &self.params;
        let ZclAttrStructDef { attrs, vis, ident, generics, field } = &self.struct_def;
        let Field { attrs: field_attrs, ty, .. } = &field;

        let variant = match variant {
            None => {
                if let Type::Path(TypePath { path, .. }) = ty {
                    let value = path.get_ident().expect("invalid type").to_string();
                    let variant = match value.as_str() {
                        "bool" => "Bool",
                        "u8" => "UInt8",
                        "u16" => "UInt16",
                        "u32" => "UInt32",
                        "u64" => "UInt64",
                        "i8" => "Int8",
                        "i16" => "Int16",
                        "i32" => "Int32",
                        "i64" => "Int64",
                        "f32" => "Float",
                        "f64" => "Double",
                        "String" => "String",
                        _ => panic!("invalid type")
                    };

                    Ident::new(variant, Span::call_site())
                } else {
                    panic!("invalid type")
                }
            }
            Some(item) => item.ident.clone(),
        };

        let zcl_data_id = get_zcl_identifier(variant.to_string());

        let default = match default {
            None => quote!(<#ty>::default()),
            Some(default) => quote!(#default),
        };

        let crate_name = match crate_name {
            None => quote!(zigbee),
            Some(segment) => quote!(#segment)
        };

        let base_path = quote!(#crate_name::zcl);

        let BaseAttribute = quote!(#base_path::cluster::types::BaseAttribute);
        let BaseReportableAttribute = quote!(#base_path::cluster::types::BaseReportableAttribute);
        let Attribute = quote!(#base_path::cluster::types::Attribute);
        let ReportedAttribute = quote!(#base_path::cluster::types::ReportedAttribute);
        let AttributeAccess = quote!(#base_path::cluster::types::AttributeAccess);
        let ReportedAttributeIntervalsConfig = quote!(#base_path::cluster::types::ReportedAttributeIntervalsConfig);
        let ZclData = quote!(#base_path::types::ZclData);
        let ZclVariant = quote!(#ZclData::#variant);
        let ZclStatus = quote!(#base_path::types::ZclStatus);

        let access = match access {
            None => quote!(#AttributeAccess::READ_ONLY),
            Some(path) => quote!(#path)
        };

        let report_config = match reported {
            None => quote!(None),
            Some((min, max, step)) => quote! {
                Some(#ReportedAttributeIntervalsConfig::<#ty>::new(
                    (#min, #max), #step
                ))
            }
        };

        let range_block = match range {
            None => quote!(Ok(())),
            Some((r_min, r_max)) => quote! {
                if #r_min <= *value && *value <= #r_max {
                    Ok(())
                } else {
                    Err(#ZclStatus::InvalidValue)
                }
            }
        };

        let reported_read_bytes_block = match reported {
            None => quote!(let intervals = None;),
            Some((min, max, step)) => quote! {
                let min: u16 = bytes.read_with(offset, byte::LE)?;
                let max: u16 = bytes.read_with(offset, byte::LE)?;

                let mut config = #ReportedAttributeIntervalsConfig::<#ty>::new((#min, #max), #step);
                let _ = config.set_values(min, max, #step);

                let intervals = Some(config);
            }
        };


        tokens.extend(quote! {
            #(#attrs)*
            #vis struct #ident #generics {
                #(#field_attrs)*
                pub value: #ty,
                report_config: Option<#ReportedAttributeIntervalsConfig<#ty>>
            }

            impl #generics #ident #generics {
                pub const ACCESS: #AttributeAccess = #access;
                pub const IDENTIFIER: u16 = #identifier;
                pub const ZCL_DATA_ID: u8 = #zcl_data_id;

                pub fn new(value: #ty) -> Self {
                    Self {
                        value,
                        report_config: #report_config,
                    }
                }
            }

            impl #generics Default for #ident #generics {
                fn default() -> Self { Self::new(#default) }
            }

            impl #generics #BaseAttribute for #ident #generics {
                fn get_identifier(&self) -> u16 { Self::IDENTIFIER }
                fn get_zcl_data_identifier(&self) -> u8 { Self::ZCL_DATA_ID }

                fn get_zcl_data(&'_ self) -> #ZclData {
                    #ZclVariant(self.value.clone().into())
                }

                fn set_from_zcl_data(&mut self, data: &#ZclData) -> Result<(), #ZclStatus> {
                    let value = match data {
                        #ZclVariant(value) => <#ty>::try_from(value.clone()).map_err(|_| #ZclStatus::InvalidValue),
                        _ => Err(#ZclStatus::InvalidDataType),
                    }?;

                    #Attribute::set_value(self, value)
                }
                fn validate_from_zcl_data(&self, data: &#ZclData) -> Result<(), #ZclStatus> {
                    let value = match data {
                        #ZclVariant(value) => <#ty>::try_from(value.clone()).map_err(|_| #ZclStatus::InvalidValue),
                        _ => Err(#ZclStatus::InvalidDataType),
                    }?;

                    #Attribute::validate_value(self, &value)?;

                    Ok(())
                }

                fn validate_zcl_data_id(&self, id: u8) -> Result<(), #ZclStatus> {
                    if id != Self::ZCL_DATA_ID {
                        return Err(#ZclStatus::InvalidDataType);
                    }

                    Ok(())
                }

                fn get_access(&self) -> #AttributeAccess { Self::ACCESS }
            }

            impl #generics #Attribute<#ty> for #ident #generics {
                fn get_value(&self) -> #ty { self.value.clone() }

                fn set_value(&mut self, value: #ty) -> Result<(), #ZclStatus> {
                    self.validate_value(&value)?;
                    self.value = value;
                    Ok(())
                }

                fn validate_value(&self, value: &#ty) -> Result<(), #ZclStatus> {
                    #range_block
                }
            }

            impl #generics byte::TryRead<'_> for #ident #generics {
                fn try_read(bytes: &[u8], _: ()) -> byte::Result<(Self, usize)> {
                    use byte;
                    use byte::BytesExt;

                    let offset = &mut 0;

                    let value: #ZclData = bytes.read_with(offset, ())?;

                    #reported_read_bytes_block

                    let value = match value {
                        #ZclVariant(value) => <#ty>::try_from(value).map_err(|_| byte::Error::BadInput { err: "invalid ZCL value received" }),
                        _ => Err(byte::Error::BadInput {err: "invalid ZCL variant received"}),
                    }?;

                    Ok((Self {
                        value,
                        report_config: intervals
                    }, *offset))
                }
            }

            impl #generics byte::TryWrite for &#ident #generics {
                fn try_write(self, bytes: &mut [u8], _: ()) -> byte::Result<usize> {
                    use byte;
                    use byte::BytesExt;
                    use #BaseAttribute;

                    let offset = &mut 0;

                    bytes.write_with(offset, self.get_zcl_data(), ())?;

                    if let Some(ref cfg) = self.report_config {
                        bytes.write_with(offset, cfg.current.0, byte::LE)?;
                        bytes.write_with(offset, cfg.current.1, byte::LE)?;
                    }

                    Ok(*offset)
                }
            }

            impl #generics byte::TryWrite for #ident #generics {
                fn try_write(self, bytes: &mut [u8], ctx: ()) -> byte::Result<usize> {
                    <&#ident #generics>::try_write(&self, bytes, ctx)
                }
            }

            impl #generics byte::TryWrite for &mut #ident #generics {
                fn try_write(self, bytes: &mut [u8], ctx: ()) -> byte::Result<usize> {
                    <&#ident #generics>::try_write(self, bytes, ctx)
                }
            }
        });

        match reported {
            None => {}
            Some(_) => tokens.extend(quote! {
                impl #generics #BaseReportableAttribute for #ident #generics {
                    fn set_reporting_config(
                        &mut self,
                        min: u16,
                        max: u16,
                        reportable_change: Option<&#ZclData>,
                    ) -> Result<(), #ZclStatus> {
                        let value = match reportable_change {
                            Some(#ZclVariant(value)) => Some(value.clone()),
                            Some(_) => return Err(#ZclStatus::InvalidDataType),
                            _ => None,
                        };

                        self.report_config
                            .as_mut()
                            .unwrap()
                            .set_values(min, max, value)
                    }

                    fn should_report(&mut self) -> bool {
                        self.report_config.as_mut().unwrap().should_report()
                    }

                    fn get_reporting_config(&self) -> (u16, u16, Option<#ZclData>) {
                        let r = self.report_config.as_ref().unwrap();
                        (
                            r.current.0,
                            r.current.1,
                            r.reportable_change.as_ref().map(|r| #ZclVariant(*r)),
                        )
                    }
                }

                impl #generics #ReportedAttribute<#ty> for #ident #generics {
                    fn set_reporting_config(
                        &mut self,
                        min: u16,
                        max: u16,
                        reportable_change: Option<#ty>,
                    ) -> Result<(), #ZclStatus> {
                        self.report_config
                            .as_mut()
                            .unwrap()
                            .set_values(min, max, reportable_change)
                    }
                }
            }),
        }
    }
}

pub struct ZclClusterParams {
    pub identifier: LitInt,
    pub cluster_type: Path,
    pub cmd_handler: Option<Expr>,
    pub update_handler: Option<Expr>,
    pub frequency: Option<LitInt>,
    pub crate_name: Option<PathSegment>,
}

impl ZclClusterParams {
    const KEYS: [&'static str; 6] = ["identifier", "cluster_type", "cmd_handler", "update_handler", "frequency", "crate"];
}

impl Parse for ZclClusterParams {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let items = Punctuated::<MetaNameValue, Token![,]>::parse_terminated(input)?;

        let items = items.iter()
            .map(|item| {
                let key = item.path
                    .get_ident()
                    .ok_or(syn::Error::new(item.span(), "invalid key"))?
                    .to_string();
                if !ZclClusterParams::KEYS.contains(&key.as_str()) {
                    return Err(syn::Error::new(item.span(), "invalid key"))
                }
                Ok((key, item.value.clone()))
            })
            .collect::<syn::Result<Vec<(String, Expr)>>>()?;
        let items = HashMap::<String, Expr>::from_iter(items);

        let identifier = items.get("identifier")
            .ok_or(syn::Error::new(input.span(), "missing identifier"))?;
        let identifier = as_lit_int(identifier)?;

        let cluster_type = as_path(items.get("cluster_type")
            .ok_or(syn::Error::new(input.span(), "missing cluster type"))?)?;

        let crate_name = items.get("crate")
            .map(|item| as_path(item)
                .unwrap()
                .segments
                .last()
                .unwrap()
                .clone()
            );

        Ok(ZclClusterParams {
            identifier,
            cluster_type,
            cmd_handler: items.get("cmd_handler").cloned(),
            update_handler: items.get("update_handler").cloned(),
            frequency: items.get("frequency")
                .map(|item| as_lit_int(item).expect("invalid frequency value")),
            crate_name
        })
    }
}

pub struct ZclClusterStructDef {
    pub attrs: Vec<Attribute>,
    pub vis: Visibility,
    pub ident: Ident,
    pub generics: Generics,
    pub fields: Vec<Field>,
    pub reportable_fields: Vec<Field>
}

impl Parse for ZclClusterStructDef {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        fn has_r_attr(field: &Field) -> bool {
            field.attrs.iter().any(|attr| if let Meta::Path(ref path) = attr.meta {
                path.get_ident().is_some_and(|item| item.to_string().as_str() == "R")
            } else {
                false
            })
        }

        let strct = ItemStruct::parse(input)?;

        let mut fields = Vec::new();
        let mut reportable_fields = Vec::new();

        if let Fields::Named(FieldsNamed { named, .. }) = strct.fields {
            for mut field in named {
                if has_r_attr(&field) {
                    field.attrs.retain(|item| item.path().get_ident().is_none_or(|ident| ident.to_string().as_str() != "R"));
                    reportable_fields.push(field.clone());
                }

                fields.push(field.clone());
            }
        } else {
            return Err(syn::Error::new(strct.fields.span(), "invalid struct definition"))
        }


        Ok(Self {
            attrs: strct.attrs,
            vis: strct.vis,
            ident: strct.ident,
            generics: strct.generics,
            fields,
            reportable_fields,
        })
    }
}

pub struct ZclCluster {
    pub params: ZclClusterParams,
    pub struct_def: ZclClusterStructDef,
}

impl ToTokens for ZclCluster {
    #[allow(non_snake_case)]
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let ZclClusterParams { identifier, cluster_type, cmd_handler, update_handler, frequency, crate_name } = &self.params;
        let ZclClusterStructDef { attrs, vis, ident, generics, fields, reportable_fields } = &self.struct_def;

        let generic_idents = generics.params.clone()
            .iter()
            .map(|param| match param {
                GenericParam::Lifetime(lifetime) => lifetime.lifetime.ident.clone(),
                GenericParam::Type(ty) => ty.ident.clone(),
                GenericParam::Const(cnst) => cnst.ident.clone(),
            })
            .collect::<Punctuated<Ident, Token![,]>>();

        let crate_name = match crate_name {
            None => quote!(zigbee),
            Some(segment) => quote!(#segment),
        };

        let ctx_type = generics.params.iter()
            .filter_map(|item| if let GenericParam::Type(type_param) = item {
                Some(type_param.clone())
            } else {
                None
            })
            .collect::<Vec<_>>()
            .first()
            .map(|param| param.ident.clone());

        fn is_ctx_field(field: &&Field, ctx_type: &String) -> bool {
            if let Type::Path(ref type_path) = field.ty {
                type_path.path.get_ident().map_or(false, |ident| ident.to_string().eq(ctx_type))
            } else {
                false
            }
        }

        let ctx_field = match ctx_type {
            None => None,
            Some(ref ctx_type) => fields
                .iter()
                .find(|item| is_ctx_field(item, &ctx_type.to_string()))
        };

        let other_fields = fields
            .iter()
            .filter(|item| if let Some(ctx_type) = &ctx_type {
                !is_ctx_field(item, &ctx_type.to_string())
            } else {
                true
            })
            .collect::<Vec<_>>();

        let other_field_idents = other_fields
            .iter()
            .map(|field| field.ident.clone().unwrap())
            .collect::<Vec<_>>();

        let field_names = other_field_idents.iter().map(|field| field.clone());
        let field_names_2 = field_names.clone();
        let field_names_3 = field_names.clone();
        let field_names_4 = field_names.clone();

        let field_types = fields.iter().map(|field| field.ty.clone());
        let field_types_2 = field_types.clone();

        let reportable_field_names = reportable_fields.iter().map(|item| item.ident.clone());
        let reportable_field_names_2 = reportable_field_names.clone();

        let reportable_field_types = reportable_fields.iter().map(|item| item.ty.clone());
        let reportable_field_types_2 = reportable_field_types.clone();

        let cmd_handler = cmd_handler.iter();
        let update_handler = update_handler.iter();
        let frequency = frequency.iter();

        let base_path = quote!(#crate_name::zcl);

        let BaseAttribute = quote!(#base_path::cluster::types::BaseAttribute);
        let BaseReportableAttribute = quote!(#base_path::cluster::types::BaseReportableAttribute);
        let ClusterType = quote!(#base_path::cluster::types::ClusterType);
        let ZclCluster = quote!(#base_path::cluster::types::ZclCluster);
        let ZclFrameCommand = quote!(#base_path::frame::ZclFrameCommand);
        let SpecificZclCommand = quote!(#base_path::frame::SpecificZclCommand);

        let ctx_field_ident = ctx_field
            .map(|field| field.ident.clone().unwrap());

        let ctx_field_ident_iter = ctx_field_ident.iter();
        let ctx_field_ident_iter_2 = ctx_field_ident.iter();
        let ctx_type_iter = ctx_type.iter();

        tokens.extend(quote! {
            #(#attrs)*
            #vis struct #ident #generics {
                #(#fields),*
            }

            impl #generics #ident <#generic_idents> {
                pub const IDENTIFIER: u16 = #identifier;
                pub const TYPE: #ClusterType = #cluster_type;

                pub fn new(#(#ctx_field_ident_iter: #ctx_type_iter)*) -> Self {
                    Self {
                        #(#ctx_field_ident_iter_2,)*
                        #(#other_field_idents: Default::default()),*
                    }
                }
            }

            impl #generics #ZclCluster for #ident <#generic_idents> {
                fn get_identifier(&self) -> u16 { Self::IDENTIFIER }
                fn get_type(&self) -> #ClusterType { Self::TYPE }

                #(
                    fn handle_custom_command(&mut self, cmd: &#SpecificZclCommand) -> Option<#ZclFrameCommand> {
                        #cmd_handler(self, cmd)
                    }
                )*

                #(
                    fn update(&mut self) -> () {
                        #update_handler(self)
                    }
                )*

                #(
                    fn update_frequency(&self) -> u8 {
                        #frequency
                    }
                )*

                fn get_attributes(&self) -> zb_types::HashMap<u16, &dyn #BaseAttribute, 32> {
                    let mut map: zb_types::HashMap<u16, &dyn #BaseAttribute, 32> = zb_types::HashMap::new();
                    #(map.insert(<#field_types>::IDENTIFIER, &self.#field_names).unwrap();)*
                    map
                }

                fn get_attributes_mut(&mut self) -> zb_types::HashMap<u16, &mut dyn #BaseAttribute, 32> {
                    let mut map: zb_types::HashMap<u16, &mut dyn #BaseAttribute, 32> = zb_types::HashMap::new();
                    #(map.insert(<#field_types_2>::IDENTIFIER, &mut self.#field_names_2).unwrap();)*
                    map
                }

                fn get_reportable_attributes(&self) -> zb_types::HashMap<u16, &dyn #BaseReportableAttribute, 32> {
                    let mut map: zb_types::HashMap<u16, &dyn #BaseReportableAttribute, 32> = zb_types::HashMap::new();
                    #(map.insert(<#reportable_field_types>::IDENTIFIER, &self.#reportable_field_names).unwrap();)*;
                    map
                }

                fn get_reportable_attributes_mut(&mut self) -> zb_types::HashMap<u16, &mut dyn #BaseReportableAttribute, 32> {
                    let mut map: zb_types::HashMap<u16, &mut dyn #BaseReportableAttribute, 32> = zb_types::HashMap::new();
                    #(map.insert(<#reportable_field_types_2>::IDENTIFIER, &mut self.#reportable_field_names_2).unwrap();)*;
                    map
                }

                fn read_with(&mut self, offset: &mut usize, bytes: &[u8]) -> byte::Result<()> {
                    use byte::BytesExt;

                    #(self.#field_names_3 = bytes.read_with(offset, ())?;)*

                    Ok(())
                }

                fn write_with(&self, offset: &mut usize, bytes: &mut [u8]) -> byte::Result<usize> {
                    use byte::BytesExt;

                    #(bytes.write_with(offset, &self.#field_names_4, ())?;)*

                    Ok(*offset)
                }
            }
        })
    }
}
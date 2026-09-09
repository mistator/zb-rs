use crate::utils::{as_ty, get_attribute, int_expr};
use proc_macro2::TokenStream;
use quote::{ToTokens, quote};
use syn::spanned::Spanned;
use syn::{Fields, LitInt};

pub struct BitStructDef {
    pub name: syn::Ident,
    pub fields: Vec<BitStructField>,
    pub repr_ty: syn::Type,
}

impl syn::parse::Parse for BitStructDef {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let strct = input.parse::<syn::ItemStruct>()?;
        let name = strct.ident.clone();

        let repr_ty = get_attribute(&strct.attrs, "bit_struct")
            .ok_or(syn::Error::new_spanned(&strct, "missing `bit_struct` attribute"))?;
        let repr_ty = repr_ty
            .get("repr")
            .ok_or(syn::Error::new_spanned(&strct, "missing `repr` argument"))?;

        let fields = match strct.fields {
            Fields::Named(ref named) => named
                .named
                .iter()
                .map(|field| BitStructField::from_field((*field).clone()))
                .collect::<syn::Result<Vec<BitStructField>>>()?,
            _ => return Err(syn::Error::new(strct.span(), "invalid struct, only named fields are supported")),
        };

        Ok(Self { repr_ty: as_ty(&repr_ty)?, name, fields })
    }
}

impl ToTokens for BitStructDef {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let Self{name, fields, repr_ty, ..} = &self;
        let mut read_for_loop = TokenStream::new();
        let mut write_for_loop = TokenStream::new();
        let mut field_names = TokenStream::new();

        for bit_struct in fields {
            let BitStructField{field, len, skip, ctx} = &bit_struct;
            let field_ty = &field.ty;
            let ctx = match ctx {
                None => {
                    if let syn::Type::Path(syn::TypePath { path, .. }) = field_ty {
                        if path.is_ident("bool") {
                            quote!(())
                        } else {
                            quote!(byte::LE)
                        }
                    } else {
                        quote!(byte::LE)
                    }
                },
                Some(ctx) => quote!(#ctx),
            };
            let field_name = field.ident.clone().unwrap();

            field_names.extend(quote!(#field_name, ));

            read_for_loop.extend(quote! {
                let mut byte_idx = byte_offset;
                let bit_len = #len;
                bit_offset += #skip;

                if bit_offset >= 8 {
                    bit_offset -= 8;
                    byte_offset += 1;
                    byte_idx = byte_offset;
                }

                let mask = (0b11111111 >> (8 - bit_len)) << bit_offset;
                let value = (bytes[byte_idx] & mask) >> bit_offset;

                let ctx = #ctx;
                let (#field_name, _) = <#field_ty>::try_read(&[value], ctx)?;

                bit_offset += bit_len;
                if bit_offset >= 8 {
                    bit_offset = 0;
                    byte_offset += 1;
                }
            });

            write_for_loop.extend(quote! {
                let mut byte_idx = byte_offset;
                let bit_len = #len;
                bit_offset += #skip;

                if bit_offset >= 8 {
                    bit_offset -= 8;
                    byte_offset += 1;
                    byte_idx = byte_offset;
                }

                let mask = (0b11111111 >> (8 - bit_len));
                let mut value = [0u8; 1];
                let ctx = #ctx;

                value.as_mut_slice().write_with(&mut 0, *#field_name, ctx)?;
                bytes[byte_idx] |= (value[0] & mask) << bit_offset;

                bit_offset += bit_len;
                if bit_offset >= 8 {
                    bit_offset = 0;
                    byte_offset += 1;
                }
            });
        }

        tokens.extend(quote!{
            impl #name {
                pub fn get_value(&self) -> #repr_ty {
                    use ::byte::TryWrite;

                    let mut bytes = [0u8; size_of::<#repr_ty>()];
                    self.try_write(&mut bytes, byte::LE).unwrap();
                    <#repr_ty>::from_le_bytes(bytes)
                }

                pub fn new(value: #repr_ty) -> Self {
                    use ::byte::TryRead;
                    Self::try_read(&value.to_le_bytes(), ()).unwrap().0
                }
            }

            impl From<#name> for #repr_ty {
                fn from(value: #name) -> Self {
                    value.get_value()
                }
            }

            impl TryFrom<#repr_ty> for #name {
                type Error = byte::Error;

                fn try_from(value: #repr_ty) -> Result<Self, Self::Error> {
                    Ok(Self::new(value))
                }
            }

            impl<C> ::byte::TryRead<'_, C> for #name {
                fn try_read(bytes: &[u8], _: C) -> ::byte::Result<(Self, usize)> {
                    use ::byte::BytesExt;

                    byte::check_len(bytes, size_of::<#repr_ty>())?;
                    let mut byte_offset: usize = 0;
                    let mut bit_offset: u8 = 0;

                    #read_for_loop

                    Ok((Self {#field_names}, size_of::<#repr_ty>()))
                }
            }

            impl<C> ::byte::TryWrite<C> for &#name {
                fn try_write(self, bytes: &mut [u8], _: C) -> ::byte::Result<usize> {
                    use ::byte::BytesExt;

                    const n_bytes: usize = size_of::<#repr_ty>();

                    let mut byte_offset: usize = 0;
                    let mut bit_offset: u8 = 0;

                    let #name { #field_names } = self;

                    #write_for_loop

                    Ok(n_bytes)
                }
            }

            impl<C> ::byte::TryWrite<C> for &mut #name {
                fn try_write(self, bytes: &mut [u8], ctx: C) -> ::byte::Result<usize> {
                    <&#name>::try_write(self, bytes, ctx)
                }
            }

            impl<C> ::byte::TryWrite<C> for #name {
                fn try_write(self, bytes: &mut [u8], ctx: C) -> ::byte::Result<usize> {
                    (&self).try_write(bytes, ctx)
                }
            }
        });
    }
}

pub struct BitStructField {
    pub field: syn::Field,
    pub len: syn::LitInt,
    pub skip: syn::LitInt,
    pub ctx: Option<syn::Expr>
}

impl BitStructField {
    pub fn from_field(field: syn::Field) -> syn::Result<Self> {
        let ctx = None;
        let len = LitInt::new("1", field.span());
        let skip = LitInt::new("0", field.span());

        let Some(args) = get_attribute(&field.attrs, "bit_struct") else {
            return Ok(Self { field, len, skip, ctx, })
        };

        let ctx = args.get("ctx").cloned();
        let len = args.get("len").map_or(Ok(len), |arg| int_expr(arg))?;
        let skip = args.get("skip").map_or(Ok(skip), |arg| int_expr(arg))?;

        Ok(Self { field, len, skip, ctx })
    }
}


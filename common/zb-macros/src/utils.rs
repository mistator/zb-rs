use proc_macro2::TokenStream;
use quote::ToTokens;
use std::collections::HashMap;
use syn::{Attribute, Expr, ExprLit, ExprPath};

pub(crate) fn int_expr(expr: &syn::Expr) -> syn::Result<syn::LitInt> {
    match expr {
        syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Int(lit), .. }) => Ok(lit.clone()),
        _ => Err(syn::Error::new_spanned(expr, "expected an integer literal")),
    }
}

pub(crate) type AttrArgs = HashMap<String, syn::Expr>;

pub(crate) fn get_attribute(attrs: &Vec<Attribute>, id: &str) -> Option<AttrArgs> {
    let attr = attrs.iter()
        .find(|attr| attr.meta.path().is_ident(id))?
        .clone();

    if let syn::Meta::List(ref meta_list) = attr.meta {
        let parser = syn::punctuated::Punctuated::<syn::MetaNameValue, syn::Token![,]>::parse_terminated;
        let mut args = AttrArgs::new();
        let meta_args = meta_list.parse_args_with(parser).ok()?;

        for arg in meta_args {
            args.insert(arg.path.get_ident()?.to_string(), arg.value.clone());
        }

        Some(args)
    } else {
        None
    }
}

pub(crate) fn as_ty(expr: &syn::Expr) -> syn::Result<syn::Type> {
    let mut stream = TokenStream::new();
    expr.to_tokens(&mut stream);

    syn::parse2(stream)
}

pub(crate) fn as_lit_int(expr: &syn::Expr) -> syn::Result<syn::LitInt> {
    if let Expr::Lit(ExprLit { lit: syn::Lit::Int(lit_int), .. } ) = expr {
        Ok(lit_int.clone())
    } else {
        Err(syn::Error::new_spanned(expr, "expected an integer literal"))
    }
}

pub(crate) fn as_path(expr: &syn::Expr) -> syn::Result<syn::Path> {
    if let Expr::Path(ExprPath { path, .. } ) = expr {
        Ok(path.clone())
    } else {
        Err(syn::Error::new_spanned(expr, "expected an integer literal"))
    }
}

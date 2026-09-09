mod bit_struct;
mod utils;
mod impl_block;
mod zcl;

use crate::bit_struct::BitStructDef;
use crate::impl_block::ImplBlock;
use crate::zcl::{ZclAttr, ZclAttrParams, ZclAttrStructDef, ZclCluster, ZclClusterParams, ZclClusterStructDef};
use proc_macro::TokenStream;
use quote::ToTokens;
use syn::parse_macro_input;

#[proc_macro_derive(BitStruct, attributes(bit_struct))]
pub fn bit_struct(input: TokenStream) -> TokenStream {
    let struct_def = parse_macro_input!(input as BitStructDef);
    struct_def.to_token_stream().into()
}

#[proc_macro_attribute]
pub fn try_write_impl(_: TokenStream, item: TokenStream) -> TokenStream {
    let item_impl = parse_macro_input!(item as syn::ItemImpl);
    let impl_block = ImplBlock {item_impl};
    impl_block.to_token_stream().into()
}

#[proc_macro_attribute]
pub fn zcl_attr(attrs: TokenStream, item: TokenStream) -> TokenStream {
    let params = parse_macro_input!(attrs as ZclAttrParams);
    let struct_def = parse_macro_input!(item as ZclAttrStructDef);

    let attr = ZclAttr { params, struct_def };

    attr.to_token_stream().into()
}

#[proc_macro_attribute]
pub fn zcl_cluster(attrs: TokenStream, item: TokenStream) -> TokenStream {
    let params = parse_macro_input!(attrs as ZclClusterParams);
    let struct_def = parse_macro_input!(item as ZclClusterStructDef);

    let cluster = ZclCluster { params, struct_def };

    cluster.to_token_stream().into()
}

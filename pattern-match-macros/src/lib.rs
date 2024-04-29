use proc_macro::TokenStream;
use quote::quote;
use syn::{parse::Error, parse_macro_input, LitStr};

mod ida;

#[proc_macro]
pub fn ida(input: TokenStream) -> TokenStream {
    let pattern = parse_macro_input!(input as LitStr);

    match ida::parse_ida_pattern(&pattern.value()) {
        Ok(val) => {
            let bt: Vec<_> = val.into_iter().map(|x| {
                let b = x.0;
                let m = x.1;

                quote! {
                    MaskedByte::new(#b, #m)
                }
            }).collect();

            quote! {
                [#(#bt),*]
            }
            .into()
        }
        Err(err) => {
            return Error::new(pattern.span(), err.to_string())
                .to_compile_error()
                .into();
        }
    }
}

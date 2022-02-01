use std::error::Error;
use std::ffi::IntoStringError;
use std::fmt::{Display, Formatter};

use libkrb5_sys::*;

use crate::context::Krb5Context;

#[derive(Debug)]
pub enum Krb5Error {
  LibraryError { message: String },
  NullPointerDereference,
  StringConversion { error: Option<IntoStringError> },
  MaxVarArgsExceeded,
}

impl Display for Krb5Error {
  fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
    use Krb5Error::*;

    match self {
      LibraryError { message } => write!(f, "Library error: {}", message),
      NullPointerDereference => write!(f, "NULL Pointer dereference error"),
      StringConversion { error } => match error {
        Some(error) => write!(f, "String conversion / UTF8 error: {}", error),
        None => write!(f, "String conversion / UTF8 error"),
      },
      MaxVarArgsExceeded => write!(
        f,
        "Maximum number of supported arguments for a variadic function exceeded."
      ),
    }
  }
}

impl Error for Krb5Error {}

impl From<IntoStringError> for Krb5Error {
  fn from(error: IntoStringError) -> Self {
    Krb5Error::StringConversion { error: Some(error) }
  }
}

/**
* Convert krb5 error code to a Krb5Error wrapped in a Result.
*
* # Arguments
*  * context: current Krb5Context
*  * code: libkrb5 error code
*
* # Example
```ignore
let code: krb5_error_code = unsafe { krb5_init_secure_context(context_ptr.as_mut_ptr()) };
// ...
krb5_error_code_escape_hatch(&context, code)?;
```
*
* #Returns
*
* Ok(()) if `code` is 0 or Krb5Error result.
*/
#[must_use]
pub(crate) fn krb5_error_code_escape_hatch(context: &Krb5Context, code: krb5_error_code) -> Result<(), Krb5Error> {
  if code == 0 {
    Ok(())
  } else {
    Err(Krb5Error::LibraryError {
      message: context.error_code_to_message(code),
    })
  }
}

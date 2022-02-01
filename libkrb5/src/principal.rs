/*!
 * Rustic wrapper for krb5 principals.
 */
use std::os::raw::c_char;

use libkrb5_sys::*;

use crate::context::Krb5Context;
use crate::error::Krb5Error;
use crate::strconv::c_string_to_string;

/**
 * krb5 principal wrapper struct.
 */
#[derive(Debug)]
pub struct Krb5Principal<'a> {
  pub(crate) context: &'a Krb5Context,
  pub(crate) principal: krb5_principal,
}

impl<'a> Drop for Krb5Principal<'a> {

  /**
   * Free/drop a principal.
   *
   * [krb5_free_principal](https://web.mit.edu/kerberos/krb5-1.16/doc/appdev/refs/api/krb5_free_principal.html)
   */
  fn drop(&mut self) {
    unsafe {
      krb5_free_principal(self.context.context, self.principal);
    }
  }
}

impl<'a> Krb5Principal<'a> {

  /**
   * Retrieve principal data.
   */
  pub fn data(&self) -> Krb5PrincipalData {
    Krb5PrincipalData {
      context: &self.context,
      principal_data: unsafe { *self.principal },
    }
  }
}

/**
 * Principal data wrapper struct.
 *
 * https://web.mit.edu/kerberos/krb5-1.16/doc/appdev/refs/types/krb5_principal.html#c.krb5_principal
 */
#[derive(Debug)]
pub struct Krb5PrincipalData<'a> {
  pub(crate) context: &'a Krb5Context,
  pub(crate) principal_data: krb5_principal_data,
}

impl<'a> Krb5PrincipalData<'a> {

  /**
   * Retrieve realm name from principal data.
   */
  pub fn realm(&self) -> Result<String, Krb5Error> {
    let realm: *const c_char = self.principal_data.realm.data;

    c_string_to_string(realm)
  }
}

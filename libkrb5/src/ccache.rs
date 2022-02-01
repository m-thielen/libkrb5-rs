/*!
 * Rustic wrapper for krb5 credential caches.
 */
use std::mem::MaybeUninit;
use std::os::raw::c_char;

use libkrb5_sys::*;

use crate::context::Krb5Context;
use crate::error::{krb5_error_code_escape_hatch, Krb5Error};
use crate::principal::Krb5Principal;
use crate::strconv::{c_string_to_string, string_to_c_string};

/**
 * Wrapper struct for a krb5 credential cache.
 *
 * https://web.mit.edu/kerberos/krb5-1.12/doc/basic/ccache_def.html
 */
#[derive(Debug)]
pub struct Krb5CCache<'a> {
  pub(crate) context: &'a Krb5Context,
  pub(crate) ccache: krb5_ccache,
}

/**
 * Free a credential cache instance.
 *
 * [krb5_cc_close](https://web.mit.edu/kerberos/krb5-1.16/doc/appdev/refs/api/krb5_cc_close.html)
 */
impl<'a> Drop for Krb5CCache<'a> {
  fn drop(&mut self) {
    unsafe {
      krb5_cc_close(self.context.context, self.ccache);
    }
  }
}

impl<'a> Krb5CCache<'a> {
  /**
   * Initialize using the default credential cache name.
   *
   * [krb5_cc_default](https://web.mit.edu/kerberos/krb5-1.16/doc/appdev/refs/api/krb5_cc_default.html)
   *
   * # Arguments
   *
   *  * context: the Krb5Context instance
   */
  pub fn default(context: &Krb5Context) -> Result<Krb5CCache, Krb5Error> {
    let mut ccache_ptr: MaybeUninit<krb5_ccache> = MaybeUninit::zeroed();

    let code: krb5_error_code = unsafe { krb5_cc_default(context.context, ccache_ptr.as_mut_ptr()) };

    krb5_error_code_escape_hatch(context, code)?;

    let cursor = Krb5CCache {
      context,
      ccache: unsafe { ccache_ptr.assume_init() },
    };

    Ok(cursor)
  }

  /**
   * Return the name of the default credential cache.
   *
   * [krb5_cc_default_name](https://web.mit.edu/kerberos/krb5-1.16/doc/appdev/refs/api/krb5_cc_default_name.html#c.krb5_cc_default_name)
   *
   * # Arguments
   *
   *  * context: the Krb5Context instance
   */
  pub fn default_name(context: &Krb5Context) -> Result<String, Krb5Error> {
    let name: *const c_char = unsafe { krb5_cc_default_name(context.context) };

    c_string_to_string(name)
  }

  /**
   * Destroy any existing contents of the cache and close it.
   *
   * [krb5_cc_destroy](https://web.mit.edu/kerberos/krb5-1.16/doc/appdev/refs/api/krb5_cc_destroy.html)
   */
  pub fn destroy(self) -> Result<(), Krb5Error> {
    let code = unsafe { krb5_cc_destroy(self.context.context, self.ccache) };

    krb5_error_code_escape_hatch(self.context, code)?;

    Ok(())
  }

  /**
   * Duplicate a credential cache handle.
   *
   * This is commented out since it is not available in Heimdal Kerberos.
   */
  // pub fn dup(&self) -> Result<Krb5CCache, Krb5Error> {
  //     let mut ccache_ptr: MaybeUninit<krb5_ccache> = MaybeUninit::zeroed();

  //     let code: krb5_error_code = unsafe { krb5_cc_dup(self.context.context, self.ccache, ccache_ptr.as_mut_ptr()) };

  //     krb5_error_code_escape_hatch(self.context, code)?;

  //     let ccache = Krb5CCache {
  //         context: self.context,
  //         ccache: unsafe { ccache_ptr.assume_init() },
  //     };

  //     Ok(ccache)
  // }

  /**
   * Return the name of the credential cache.
   *
   * [krb5_cc_get_name](https://web.mit.edu/kerberos/krb5-1.16/doc/appdev/refs/api/krb5_cc_get_name.html)
   */
  pub fn get_name(&self) -> Result<String, Krb5Error> {
    let name: *const c_char = unsafe { krb5_cc_get_name(self.context.context, self.ccache) };
    c_string_to_string(name)
  }

  /**
   * Retrieve default principal of a credential cache.
   *
   * [krb5_cc_get_principal](https://web.mit.edu/kerberos/krb5-1.16/doc/appdev/refs/api/krb5_cc_get_principal.html)
   */
  pub fn get_principal(&self) -> Result<Option<Krb5Principal>, Krb5Error> {
    let mut principal_ptr: MaybeUninit<krb5_principal> = MaybeUninit::zeroed();

    let code: krb5_error_code =
      unsafe { krb5_cc_get_principal(self.context.context, self.ccache, principal_ptr.as_mut_ptr()) };

    krb5_error_code_escape_hatch(self.context, code)?;

    let principal_ptr = unsafe { principal_ptr.assume_init() };

    if principal_ptr.is_null() {
      return Ok(None);
    }

    let principal = Krb5Principal {
      context: &self.context,
      principal: principal_ptr,
    };

    Ok(Some(principal))
  }

  /**
   * Get the type of the credential cache.
   *
   * [krb5_cc_get_type](https://web.mit.edu/kerberos/krb5-1.16/doc/appdev/refs/api/krb5_cc_get_type.html)
   */
  pub fn get_type(&self) -> Result<String, Krb5Error> {
    let cctype: *const c_char = unsafe { krb5_cc_get_type(self.context.context, self.ccache) };

    c_string_to_string(cctype)
  }

  /**
   * Initialize a credential cache.
   *
   * [krb5_cc_initialize](https://web.mit.edu/kerberos/krb5-1.16/doc/appdev/refs/api/krb5_cc_initialize.html)
   */
  pub fn initialize(&mut self, principal: &Krb5Principal) -> Result<(), Krb5Error> {
    let code: krb5_error_code = unsafe { krb5_cc_initialize(self.context.context, self.ccache, principal.principal) };

    krb5_error_code_escape_hatch(self.context, code)?;

    Ok(())
  }

  /**
   * Create a new credential cache of the specified type with a unique name.
   *
   * [krb5_cc_new_unique](https://web.mit.edu/kerberos/krb5-1.16/doc/appdev/refs/api/krb5_cc_new_unique.html)
   *
   * # Arguments
   *
   *  * context: the Krb5Context instance
   *  * cctype: the credential cache [type name](https://web.mit.edu/kerberos/krb5-1.12/doc/basic/ccache_def.html#ccache-types)
   *
   */
  pub fn new_unique(context: &'a Krb5Context, cctype: &str) -> Result<Krb5CCache<'a>, Krb5Error> {
    let cctype = string_to_c_string(cctype)?;

    let mut ccache_ptr: MaybeUninit<krb5_ccache> = MaybeUninit::zeroed();

    let code: krb5_error_code =
      unsafe { krb5_cc_new_unique(context.context, cctype, std::ptr::null(), ccache_ptr.as_mut_ptr()) };

    krb5_error_code_escape_hatch(context, code)?;

    let cursor = Krb5CCache {
      context,
      ccache: unsafe { ccache_ptr.assume_init() },
    };

    Ok(cursor)
  }

  /**
   * Resolve a credential cache name.
   *
   * [krb5_cc_resolve]  (https://web.mit.edu/kerberos/krb5-1.16/doc/appdev/refs/api/krb5_cc_resolve.html)
   *
   * # Arguments
   *
   *  * context: the Krb5Context instance
   *  * name: the credential cache name to be resolved
   *
   */
  pub fn resolve(context: &'a Krb5Context, name: &str) -> Result<Krb5CCache<'a>, Krb5Error> {
    let name = string_to_c_string(name)?;

    let mut ccache_ptr: MaybeUninit<krb5_ccache> = MaybeUninit::zeroed();

    let code: krb5_error_code = unsafe { krb5_cc_resolve(context.context, name, ccache_ptr.as_mut_ptr()) };

    krb5_error_code_escape_hatch(context, code)?;

    let cursor = Krb5CCache {
      context,
      ccache: unsafe { ccache_ptr.assume_init() },
    };

    Ok(cursor)
  }
}

/*!
 * Rustic wrapper for krb5 credential cache collections.
 */
use std::mem::MaybeUninit;

use libkrb5_sys::*;

use crate::ccache::Krb5CCache;
use crate::context::Krb5Context;
use crate::error::{krb5_error_code_escape_hatch, Krb5Error};

/**
 * Kerberos credential cache collection struct
 *
 * https://web.mit.edu/kerberos/krb5-1.12/doc/basic/ccache_def.html#collections-of-caches
 */
#[derive(Debug)]
pub struct Krb5CCCol<'a> {
  pub(crate) context: &'a Krb5Context,
  pub(crate) cursor: krb5_cccol_cursor,
}

impl<'a> Krb5CCCol<'a> {

  /**
   * Initialize a credential cache collection.
   *
   * Creates krb5 credential cache collection cursor that can be iterated over later.
   * [krb5_cccol_cursor_new](https://web.mit.edu/kerberos/krb5-1.16/doc/appdev/refs/api/krb5_cccol_cursor_new.html)
   */
  pub fn new(context: &Krb5Context) -> Result<Krb5CCCol, Krb5Error> {
    let mut cursor_ptr: MaybeUninit<krb5_cccol_cursor> = MaybeUninit::zeroed();

    let code: krb5_error_code = unsafe { krb5_cccol_cursor_new(context.context, cursor_ptr.as_mut_ptr()) };

    krb5_error_code_escape_hatch(context, code)?;

    let cursor = Krb5CCCol {
      context: &context,
      cursor: unsafe { cursor_ptr.assume_init() },
    };

    Ok(cursor)
  }
}

impl<'a> Drop for Krb5CCCol<'a> {

  /**
   * Free a credential cache collection.
   *
   * Wraps [krb5_cccol_cursor_free](https://web.mit.edu/kerberos/krb5-1.16/doc/appdev/refs/api/krb5_cccol_cursor_free.html)
   */
  fn drop(&mut self) {
    unsafe {
      krb5_cccol_cursor_free(self.context.context, &mut self.cursor);
    }
  }
}

/**
 * Implement Rustic iterator for a Kerberos credential cache collection.
 */
impl<'a> Iterator for Krb5CCCol<'a> {
  type Item = Result<Krb5CCache<'a>, Krb5Error>;

  fn next(&mut self) -> Option<Self::Item> {
    let mut ccache_ptr: MaybeUninit<krb5_ccache> = MaybeUninit::zeroed();

    let code: krb5_error_code =
      unsafe { krb5_cccol_cursor_next(self.context.context, self.cursor, ccache_ptr.as_mut_ptr()) };

    krb5_error_code_escape_hatch(self.context, code).ok()?;

    let ccache_ptr = unsafe { ccache_ptr.assume_init() };

    if ccache_ptr.is_null() {
      return None;
    }

    let ccache = Krb5CCache {
      context: &self.context,
      ccache: ccache_ptr,
    };

    Some(Ok(ccache))
  }
}

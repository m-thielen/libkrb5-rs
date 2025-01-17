/*!
 * "Safe" Rust wrapper for krb5 library context.
 *
 */
use std::mem::MaybeUninit;
use std::os::raw::c_char;
use std::sync::Mutex;

use lazy_static::lazy_static;
use libkrb5_sys::*;

use crate::error::{krb5_error_code_escape_hatch, Krb5Error};
use crate::principal::Krb5Principal;
use crate::strconv::{c_string_to_string, string_to_c_string};

lazy_static! {
    /**
     * The kerberos client library is thread safe, except for the init functions.
     * This Mutex protects init functions from concurrent usage.
     */
    static ref CONTEXT_INIT_LOCK: Mutex<()> = Mutex::new(());
}

/**
 * Wrapper struct for `krb5_context_data`.
 */
#[derive(Debug)]
pub struct Krb5Context {
  pub(crate) context: krb5_context,
}

impl Krb5Context {
  /**
   * Initialize krb5 context.
   *
   * Wraps [krb5_init_context](https://web.mit.edu/kerberos/krb5-1.16/doc/appdev/refs/api/krb5_init_context.html)
   */
  pub fn init() -> Result<Krb5Context, Krb5Error> {
    let _guard = CONTEXT_INIT_LOCK
      .lock()
      .expect("Failed to lock context initialization.");

    let mut context_ptr: MaybeUninit<krb5_context> = MaybeUninit::zeroed();

    let code: krb5_error_code = unsafe { krb5_init_context(context_ptr.as_mut_ptr()) };

    let context = Krb5Context {
      context: unsafe { context_ptr.assume_init() },
    };

    krb5_error_code_escape_hatch(&context, code)?;

    Ok(context)
  }

  /**
   * Init krb5 context using only config files.
   *
   * Wraps [krb5_init_secure_context](https://web.mit.edu/kerberos/krb5-1.16/doc/appdev/refs/api/krb5_init_secure_context.html)
   */
  pub fn init_secure() -> Result<Krb5Context, Krb5Error> {
    let _guard = CONTEXT_INIT_LOCK
      .lock()
      .expect("Failed to lock context initialization.");

    let mut context_ptr: MaybeUninit<krb5_context> = MaybeUninit::zeroed();

    let code: krb5_error_code = unsafe { krb5_init_secure_context(context_ptr.as_mut_ptr()) };

    let context = Krb5Context {
      context: unsafe { context_ptr.assume_init() },
    };

    krb5_error_code_escape_hatch(&context, code)?;

    Ok(context)
  }

  /**
   * Build a principal name using a realm and 1 or more strings.
   *
   * Wraps [krb5_build_principal](https://web.mit.edu/kerberos/krb5-1.16/doc/appdev/refs/api/krb5_build_principal.html)
   */

  pub fn build_principal<'a>(&'a self, realm: &'a str, args: &'a [String]) -> Result<Krb5Principal<'a>, Krb5Error> {
    let crealm = string_to_c_string(realm)?;
    let realml = realm.len() as u32;

    let mut varargs = Vec::new();
    for arg in args {
      varargs.push(string_to_c_string(arg)?);
    }

    let mut principal_ptr: MaybeUninit<krb5_principal> = MaybeUninit::zeroed();

    // TODO: write a macro to generate this match block
    let code: krb5_error_code = match args.len() {
      // varargs support in Rust is lacking, so only support a limited number of arguments for now
      0 => unsafe { krb5_build_principal(self.context, principal_ptr.as_mut_ptr(), realml, crealm) },
      1 => unsafe { krb5_build_principal(self.context, principal_ptr.as_mut_ptr(), realml, crealm, varargs[0]) },
      2 => unsafe {
        krb5_build_principal(
          self.context,
          principal_ptr.as_mut_ptr(),
          realml,
          crealm,
          varargs[0],
          varargs[1],
        )
      },
      3 => unsafe {
        krb5_build_principal(
          self.context,
          principal_ptr.as_mut_ptr(),
          realml,
          crealm,
          varargs[0],
          varargs[1],
          varargs[2],
        )
      },
      4 => unsafe {
        krb5_build_principal(
          self.context,
          principal_ptr.as_mut_ptr(),
          realml,
          crealm,
          varargs[0],
          varargs[1],
          varargs[2],
          varargs[3],
        )
      },
      _ => return Err(Krb5Error::MaxVarArgsExceeded),
    };

    krb5_error_code_escape_hatch(self, code)?;

    let principal = Krb5Principal {
      context: self,
      principal: unsafe { principal_ptr.assume_init() },
    };

    Ok(principal)
  }

  /**
   * Retrieve the default realm.
   *
   * Wraps [krb5_get_default_realm](https://web.mit.edu/kerberos/krb5-1.16/doc/appdev/refs/api/krb5_get_default_realm.html)
   */
  pub fn get_default_realm(&self) -> Result<Option<String>, Krb5Error> {
    let mut realm: MaybeUninit<*mut c_char> = MaybeUninit::zeroed();

    let code: krb5_error_code = unsafe { krb5_get_default_realm(self.context, realm.as_mut_ptr()) };

    if code == KRB5_CONFIG_NODEFREALM {
      return Ok(None);
    }

    krb5_error_code_escape_hatch(self, code)?;

    let realm = unsafe { realm.assume_init() };

    let string = c_string_to_string(realm)?;
    unsafe { krb5_free_default_realm(self.context, realm) };

    Ok(Some(string))
  }

  /**
   * Get Kerberos realm names for a host.
   *
   * Wraps [krb5_get_host_realm](https://web.mit.edu/kerberos/krb5-1.16/doc/appdev/refs/api/krb5_get_host_realm.html)
   */
  pub fn get_host_realms(&self, host: Option<&str>) -> Result<Vec<String>, Krb5Error> {
    let c_host = match host {
      Some(host) => string_to_c_string(host)?,
      None => std::ptr::null(),
    };

    let mut c_realms: MaybeUninit<*mut *mut c_char> = MaybeUninit::zeroed();

    let code: krb5_error_code = unsafe { krb5_get_host_realm(self.context, c_host, c_realms.as_mut_ptr()) };
    krb5_error_code_escape_hatch(self, code)?;

    let c_realms = unsafe { c_realms.assume_init() };

    let mut realms: Vec<String> = Vec::new();
    let mut index: isize = 0;
    loop {
      let ptr = unsafe { *c_realms.offset(index) };

      if ptr.is_null() {
        break;
      }

      realms.push(c_string_to_string(ptr)?);

      index += 1;
    }

    unsafe { krb5_free_host_realm(self.context, c_realms) };

    Ok(realms)
  }

  /**
   * Canonicalize a hostname, possibly using name service.
   *
   * Wraps [krb5_expand_hostname](https://web.mit.edu/kerberos/krb5-1.16/doc/appdev/refs/api/krb5_expand_hostname.html)
   */
  /* TODO: this produces invalid UTF-8?
  pub fn expand_hostname(&self, hostname: &str) -> Result<String, Krb5Error> {
      let hostname_c = string_to_c_string(hostname)?;
      let mut cstr_ptr: MaybeUninit<*mut c_char> = MaybeUninit::zeroed();

      let code: krb5_error_code = unsafe { krb5_expand_hostname(self.context, hostname_c, cstr_ptr.as_mut_ptr()) };

      krb5_error_code_escape_hatch(self, code)?;
      let cstr_ptr = unsafe { cstr_ptr.assume_init() };

      let result = c_string_to_string(cstr_ptr);
      unsafe { krb5_free_string(self.context, cstr_ptr) };

      result
  }
  */

  /**
   * Get error message to a krb5 error code.
   *
   * Wraps [krb5_get_error_message](https://web.mit.edu/kerberos/krb5-1.16/doc/appdev/refs/api/krb5_get_error_message.html)
   */
  pub(crate) fn error_code_to_message(&self, code: krb5_error_code) -> String {
    let message: *const c_char = unsafe { krb5_get_error_message(self.context, code) };

    match c_string_to_string(message) {
      Ok(string) => {
        unsafe { krb5_free_error_message(self.context, message) };
        string
      }
      Err(error) => error.to_string(),
    }
  }
}

/**
 * Free a Krb5Context.
 *
 * Wraps [krb5_free_context](https://web.mit.edu/kerberos/krb5-1.16/doc/appdev/refs/api/krb5_free_context.html)
 */
impl Drop for Krb5Context {
  fn drop(&mut self) {
    let _guard = CONTEXT_INIT_LOCK
      .lock()
      .expect("Failed to lock context for de-initialization.");

    unsafe { krb5_free_context(self.context) };
  }
}

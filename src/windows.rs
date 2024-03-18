#![allow(unused)]

/// ODBC Trace DLL Functions
/// Each trace function has a corresponding ODBC function with Trace prepended.
/// The ODBC functions and documentation came be in [odbc-sys](https://github.com/pacman82/odbc-sys/blob/main/src/functions.rs).
use std::{fs, process, slice};
use std::ffi::OsString;
use std::fs::File;

use odbc_sys::{
    BulkOperation, CDataType, Char, CompletionType, ConnectionAttribute, Desc, DriverConnectOption,
    EnvironmentAttribute, FetchOrientation, FreeStmtOption, HDbc, HDesc, HEnv, HStmt, HWnd, Handle,
    HandleType, InfoType, Integer, Len, Lock, Nullability, Operation, ParamType, Pointer, RetCode,
    SetPosIRow, SmallInt, SqlDataType, SqlReturn, StatementAttribute, ULen, USmallInt, WChar,
};

use std::io::Write;
use std::os::windows::ffi::OsStringExt;
use std::sync::Mutex;
use chrono::Utc;
use widestring::{U16CString, Utf16String};
use windows::Win32::Foundation::HINSTANCE;
use windows::Win32::System::SystemServices::{DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH};

struct LogData {
    file: Option<File>
}

static GLOBAL_DATA: Mutex<LogData> = Mutex::new(LogData {
    file: None,
});

#[no_mangle]
pub extern "system" fn DllMain(
    _dll_handle: HINSTANCE,
    call_reason: DWORD,
    _reserved: *mut (),
) -> bool {
    match call_reason {
        DLL_PROCESS_ATTACH => {
            let mut data = GLOBAL_DATA.lock().unwrap();
        },
        DLL_PROCESS_DETACH => {
            GLOBAL_DATA.lock().unwrap().file = None;
        },
        _ => (),
    }
    true
}

type DWORD = u32;
/// LWPSTR is a pointer to a wide character string. The string may be null-terminated or not.
/// The length of the string is not known. It is not safe to use any data in the string.
type LPWSTR = *const u16;//*const WChar;
#[no_mangle]
pub extern "stdcall" fn TraceCloseLogFile() -> RetCode {
    if let Some(file) = GLOBAL_DATA.lock().unwrap().file.take() {
        file.sync_all().unwrap();
        GLOBAL_DATA.lock().unwrap().file = None;
    }
    
    0
}

#[no_mangle]
pub extern "stdcall" fn TraceOpenLogFile(
    sz_file_name: LPWSTR,
    lpwsz_output_msg: LPWSTR,
    cb_output_msg: DWORD,
) -> RetCode {
    let path = from_lpwstr(sz_file_name);

    if let Ok(path) = path {

        let file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();

        GLOBAL_DATA.lock().unwrap().file = Some(file);
    }

    0
}

#[no_mangle]
pub extern "stdcall" fn TraceReturn(s: RetCode, b: RetCode) {
}

#[no_mangle]
pub extern "stdcall" fn TraceSQLAllocHandle(
    handle_type: HandleType,
    input_handle: Handle,
    output_handle: *mut Handle,
) -> SqlReturn {
    SqlReturn::SUCCESS
}

#[no_mangle]
pub extern "stdcall" fn TraceSQLBindCol(
    statement_handle: HStmt,
    col_number: USmallInt,
    target_type: CDataType,
    target_value: Pointer,
    buffer_length: Len,
    length_or_indicator: *mut Len,
) -> SqlReturn {
    SqlReturn::SUCCESS
}

#[no_mangle]
pub extern "stdcall" fn TraceSQLBindParameter(
    statement_handle: HStmt,
    parameter_number: USmallInt,
    input_output_type: ParamType,
    value_type: CDataType,
    parameter_type: SqlDataType,
    column_size: ULen,
    decimal_digits: SmallInt,
    parameter_value_ptr: Pointer,
    buffer_length: Len,
    str_len_or_ind_ptr: *mut Len,
) -> SqlReturn {
    SqlReturn::SUCCESS
}

#[no_mangle]
pub extern "stdcall" fn TraceSQLBrowseConnectW(
    connection_handle: HDbc,
    in_connection_string: *const WChar,
    string_length: SmallInt,
    out_connection_string: *mut WChar,
    buffer_length: SmallInt,
    out_buffer_length: *mut SmallInt,
) -> SqlReturn {
    SqlReturn::SUCCESS
}

#[no_mangle]
pub extern "stdcall" fn TraceSQLBulkOperations(
    statement_handle: HStmt,
    operation: BulkOperation,
) -> SqlReturn {
    SqlReturn::SUCCESS
}

#[no_mangle]
pub extern "stdcall" fn TraceSQLCancel(statement_handle: HStmt) -> SqlReturn {
    SqlReturn::SUCCESS
}

#[no_mangle]
pub extern "stdcall" fn TraceSQLCancelHandle(handle_type: HandleType, handle: Handle) -> SqlReturn {
    SqlReturn::SUCCESS
}

#[no_mangle]
pub extern "stdcall" fn TraceSQLCloseCursor(statement_handle: HStmt) -> SqlReturn {
    SqlReturn::SUCCESS
}

#[no_mangle]
pub extern "stdcall" fn TraceSQLColAttribute(
    statement_handle: HStmt,
    column_number: USmallInt,
    field_identifier: Desc,
    character_attribute_ptr: Pointer,
    buffer_length: SmallInt,
    string_length_ptr: *mut SmallInt,
    numeric_attribute_ptr: *mut Len,
) -> SqlReturn {
    SqlReturn::SUCCESS
}

#[no_mangle]
pub extern "stdcall" fn TraceSQLColAttributeW(
    statement_handle: HStmt,
    column_number: USmallInt,
    field_identifier: Desc,
    character_attribute_ptr: Pointer,
    buffer_length: SmallInt,
    string_length_ptr: *mut SmallInt,
    numeric_attribute_ptr: *mut Len,
) -> SqlReturn {
    SqlReturn::SUCCESS
}

#[no_mangle]
pub extern "stdcall" fn TraceSQLColumnPrivilegesW(
    statement_handle: HStmt,
    catalog_name: *const WChar,
    catalog_name_length: SmallInt,
    schema_name: *const WChar,
    schema_name_length: SmallInt,
    table_name: *const WChar,
    table_name_length: SmallInt,
    column_name: *const WChar,
    column_name_length: SmallInt,
) -> SqlReturn {
    SqlReturn::SUCCESS
}

#[no_mangle]
pub extern "stdcall" fn TraceSQLColumnsW(
    statement_handle: HStmt,
    catalog_name: *const WChar,
    catalog_name_length: SmallInt,
    schema_name: *const WChar,
    schema_name_length: SmallInt,
    table_name: *const WChar,
    table_name_length: SmallInt,
    column_name: *const WChar,
    column_name_length: SmallInt,
) -> SqlReturn {
    SqlReturn::SUCCESS
}

#[no_mangle]
pub extern "stdcall" fn TraceSQLCompleteAsync(
    handle_type: HandleType,
    handle: Handle,
    async_ret_code_ptr: *mut RetCode,
) -> SqlReturn {
    SqlReturn::SUCCESS
}

#[no_mangle]
pub extern "stdcall" fn TraceSQLConnect(
    connection_handle: HDbc,
    server_name: *const Char,
    name_length_1: SmallInt,
    user_name: *const Char,
    name_length_2: SmallInt,
    authentication: *const Char,
    name_length_3: SmallInt,
) -> SqlReturn {
    SqlReturn::SUCCESS
}

#[no_mangle]
pub extern "stdcall" fn TraceSQLConnectW(
    connection_handle: HDbc,
    server_name: *const WChar,
    name_length_1: SmallInt,
    user_name: *const WChar,
    name_length_2: SmallInt,
    authentication: *const WChar,
    name_length_3: SmallInt,
) -> SqlReturn {
    SqlReturn::SUCCESS
}

#[no_mangle]
pub extern "stdcall" fn TraceSQLCopyDesc(
    source_desc_handle: HDesc,
    target_desc_handle: HDesc,
) -> SqlReturn {
    SqlReturn::SUCCESS
}

#[no_mangle]
pub extern "stdcall" fn TraceSQLDataSources(
    environment_handle: HEnv,
    direction: FetchOrientation,
    server_name: *mut Char,
    buffer_length_1: SmallInt,
    name_length_1: *mut SmallInt,
    description: *mut Char,
    buffer_length_2: SmallInt,
    name_length_2: *mut SmallInt,
) -> SqlReturn {
    SqlReturn::SUCCESS
}

#[no_mangle]
pub extern "stdcall" fn TraceSQLDataSourcesW(
    environment_handle: HEnv,
    direction: FetchOrientation,
    server_name: *mut WChar,
    buffer_length_1: SmallInt,
    name_length_1: *mut SmallInt,
    description: *mut WChar,
    buffer_length_2: SmallInt,
    name_length_2: *mut SmallInt,
) -> SqlReturn {
    SqlReturn::SUCCESS
}

#[no_mangle]
pub extern "stdcall" fn TraceSQLDescribeCol(
    statement_handle: HStmt,
    col_number: USmallInt,
    col_name: *mut Char,
    buffer_length: SmallInt,
    name_length: *mut SmallInt,
    data_type: *mut SqlDataType,
    col_size: *mut ULen,
    decimal_digits: *mut SmallInt,
    nullable: *mut Nullability,
) -> SqlReturn {
    SqlReturn::SUCCESS
}

#[no_mangle]
pub extern "stdcall" fn TraceSQLDescribeColW(
    statement_handle: HStmt,
    col_number: USmallInt,
    col_name: *mut WChar,
    buffer_length: SmallInt,
    name_length: *mut SmallInt,
    data_type: *mut SqlDataType,
    col_size: *mut ULen,
    decimal_digits: *mut SmallInt,
    nullable: *mut Nullability,
) -> SqlReturn {
    SqlReturn::SUCCESS
}

#[no_mangle]
pub extern "stdcall" fn TraceSQLDescribeParam(
    statement_handle: HStmt,
    parameter_number: USmallInt,
    data_type_ptr: *mut SqlDataType,
    parameter_size_ptr: *mut ULen,
    decimal_digits_ptr: *mut SmallInt,
    nullable_ptr: *mut Nullability,
) -> SqlReturn {
    SqlReturn::SUCCESS
}

#[no_mangle]
pub extern "stdcall" fn TraceSQLDisconnect(connection_handle: HDbc) -> SqlReturn {
    SqlReturn::SUCCESS
}

#[no_mangle]
pub extern "stdcall" fn TraceSQLDriverConnect(
    connection_handle: HDbc,
    window_handle: HWnd,
    in_connection_string: *const Char,
    string_length_1: SmallInt,
    out_connection_string: *mut Char,
    buffer_length: SmallInt,
    string_length_2: *mut SmallInt,
    driver_completion: DriverConnectOption,
) -> SqlReturn {
    SqlReturn::SUCCESS
}

#[no_mangle]
pub extern "stdcall" fn TraceSQLDriverConnectW(
    connection_handle: HDbc,
    window_handle: HWnd,
    in_connection_string: *const WChar,
    string_length_1: SmallInt,
    out_connection_string: *mut WChar,
    buffer_length: SmallInt,
    string_length_2: *mut SmallInt,
    driver_completion: DriverConnectOption,
) -> SqlReturn {
    SqlReturn::SUCCESS
}

#[no_mangle]
pub extern "stdcall" fn TraceSQLDrivers(
    environment_handle: HEnv,
    direction: FetchOrientation,
    driver_desc: *mut Char,
    driver_desc_max: SmallInt,
    out_driver_desc: *mut SmallInt,
    driver_attributes: *mut Char,
    driver_attr_max: SmallInt,
    attributes_length_pointer: *mut SmallInt,
) -> SqlReturn {
    SqlReturn::SUCCESS
}

#[no_mangle]
pub extern "stdcall" fn TraceSQLDriversW(
    environment_handle: HEnv,
    direction: FetchOrientation,
    driver_desc: *mut WChar,
    driver_desc_max: SmallInt,
    out_driver_desc: *mut SmallInt,
    driver_attributes: *mut WChar,
    driver_attr_max: SmallInt,
    out_driver_attr: *mut SmallInt,
) -> SqlReturn {
    SqlReturn::SUCCESS
}

#[no_mangle]
pub extern "stdcall" fn TraceSQLEndTran(
    handle_type: HandleType,
    handle: Handle,
    completion_type: CompletionType,
) -> SqlReturn {
    SqlReturn::SUCCESS
}

#[no_mangle]
pub extern "stdcall" fn TraceSQLExecDirect(
    statement_handle: HStmt,
    statement_text: *const Char,
    text_length: Integer,
) -> SqlReturn {
    SqlReturn::SUCCESS
}

#[no_mangle]
pub extern "stdcall" fn TraceSQLExecDirectW(
    statement_handle: HStmt,
    statement_text: *const WChar,
    text_length: Integer,
) -> SqlReturn {

    if let Some(file) = GLOBAL_DATA.lock().unwrap().file.as_mut() {
        let query = from_wchar(statement_text, text_length as usize);

        if let Ok(query) = query {
            let utc_now = Utc::now();
            let utc_string = utc_now.to_string();
            
            file.write_all("[".as_bytes()).unwrap();
            file.write_all(utc_string.as_bytes()).unwrap();
            file.write_all("] ".as_bytes()).unwrap();
            file.write_all(query.as_bytes()).unwrap();
            file.write_all("\n".as_bytes()).unwrap();

            SqlReturn::SUCCESS
        } else {
            SqlReturn::ERROR
        }
    } else {
        SqlReturn::ERROR
    }
}

#[no_mangle]
pub extern "stdcall" fn TraceSQLExecute(statement_handle: HStmt) -> SqlReturn {
    SqlReturn::SUCCESS
}

#[no_mangle]
pub extern "stdcall" fn TraceSQLFetch(statement_handle: HStmt) -> SqlReturn {
    SqlReturn::SUCCESS
}

#[no_mangle]
pub extern "stdcall" fn TraceSQLFetchScroll(
    statement_handle: HStmt,
    fetch_orientation: FetchOrientation,
    fetch_offset: Len,
) -> SqlReturn {
    SqlReturn::SUCCESS
}

#[no_mangle]
pub extern "stdcall" fn TraceSQLForeignKeys(
    statement_handle: HStmt,
    pk_catalog_name: *const Char,
    pk_catalog_name_length: SmallInt,
    pk_schema_name: *const Char,
    pk_schema_name_length: SmallInt,
    pk_table_name: *const Char,
    pk_table_name_length: SmallInt,
    fk_catalog_name: *const Char,
    fk_catalog_name_length: SmallInt,
    fk_schema_name: *const Char,
    fk_schema_name_length: SmallInt,
    fk_table_name: *const Char,
    fk_table_name_length: SmallInt,
) -> SqlReturn {
    SqlReturn::SUCCESS
}

#[no_mangle]
pub extern "stdcall" fn TraceSQLFreeHandle(handle_type: HandleType, handle: Handle) -> SqlReturn {
    SqlReturn::SUCCESS
}

#[no_mangle]
pub extern "stdcall" fn TraceSQLFreeStmt(statement_handle: HStmt, option: FreeStmtOption) -> SqlReturn {
    SqlReturn::SUCCESS
}

#[no_mangle]
pub extern "stdcall" fn TraceSQLGetConnectAttr(
    connection_handle: HDbc,
    attribute: ConnectionAttribute,
    value_ptr: Pointer,
    buffer_length: Integer,
    string_length_ptr: *mut Integer,
) -> SqlReturn {
    SqlReturn::SUCCESS
}

#[no_mangle]
pub extern "stdcall" fn TraceSQLGetConnectAttrW(
    connection_handle: HDbc,
    attribute: ConnectionAttribute,
    value_ptr: Pointer,
    buffer_length: Integer,
    string_length_ptr: *mut Integer,
) -> SqlReturn {
    SqlReturn::SUCCESS
}

#[no_mangle]
pub extern "stdcall" fn TraceSQLGetCursorNameW(
    statement_handle: HStmt,
    cursor_name: *mut WChar,
    buffer_length: SmallInt,
    name_length_ptr: *mut SmallInt,
) -> SqlReturn {
    SqlReturn::SUCCESS
}

#[no_mangle]
pub extern "stdcall" fn TraceSQLGetData(
    statement_handle: HStmt,
    col_or_param_num: USmallInt,
    target_type: CDataType,
    target_value_ptr: Pointer,
    buffer_length: Len,
    str_len_or_ind_ptr: *mut Len,
) -> SqlReturn {
    SqlReturn::SUCCESS
}

#[no_mangle]
pub extern "stdcall" fn TraceSQLGetDescFieldW(
    descriptor_handle: HDesc,
    record_number: SmallInt,
    field_identifier: Desc,
    value_ptr: Pointer,
    buffer_length: Integer,
    string_length_ptr: *mut Integer,
) -> SqlReturn {
    SqlReturn::SUCCESS
}

#[no_mangle]
pub extern "stdcall" fn TraceSQLGetDescRecW(
    descriptor_handle: HDesc,
    record_number: SmallInt,
    name: *mut WChar,
    buffer_length: SmallInt,
    string_length_ptr: *mut SmallInt,
    type_ptr: *mut SmallInt,
    sub_type_ptr: *mut SmallInt,
    length_ptr: *mut Len,
    precision_ptr: *mut SmallInt,
    scale_ptr: *mut SmallInt,
    nullable_ptr: *mut Nullability,
) -> SqlReturn {
    SqlReturn::SUCCESS
}

#[no_mangle]
pub extern "stdcall" fn TraceSQLGetDiagFieldW(
    handle_type: HandleType,
    handle: Handle,
    record_number: SmallInt,
    diag_identifier: SmallInt,
    diag_info_ptr: Pointer,
    buffer_length: SmallInt,
    string_length_ptr: *mut SmallInt,
) -> SqlReturn {
    SqlReturn::SUCCESS
}

#[no_mangle]
pub extern "stdcall" fn TraceSQLGetDiagRec(
    handle_type: HandleType,
    handle: Handle,
    record_number: SmallInt,
    state: *mut Char,
    native_error_ptr: *mut Integer,
    message_text: *mut Char,
    buffer_length: SmallInt,
    text_length_ptr: *mut SmallInt,
) -> SqlReturn {
    SqlReturn::SUCCESS
}

#[no_mangle]
pub extern "stdcall" fn TraceSQLGetDiagRecW(
    handle_type: HandleType,
    handle: Handle,
    record_number: SmallInt,
    state: *mut WChar,
    native_error_ptr: *mut Integer,
    message_text: *mut WChar,
    buffer_length: SmallInt,
    text_length_ptr: *mut SmallInt,
) -> SqlReturn {
    SqlReturn::SUCCESS
}

#[no_mangle]
pub extern "stdcall" fn TraceSQLGetEnvAttr(
    environment_handle: HEnv,
    attribute: EnvironmentAttribute,
    value_ptr: Pointer,
    buffer_length: Integer,
    string_length: *mut Integer,
) -> SqlReturn {
    SqlReturn::SUCCESS
}

#[no_mangle]
pub extern "stdcall" fn TraceSQLGetInfo(
    connection_handle: HDbc,
    info_type: InfoType,
    info_value_ptr: Pointer,
    buffer_length: SmallInt,
    string_length_ptr: *mut SmallInt,
) -> SqlReturn {
    SqlReturn::SUCCESS
}

#[no_mangle]
pub extern "stdcall" fn TraceSQLGetInfoW(
    connection_handle: HDbc,
    info_type: InfoType,
    info_value_ptr: Pointer,
    buffer_length: SmallInt,
    string_length_ptr: *mut SmallInt,
) -> SqlReturn {
    SqlReturn::SUCCESS
}

#[no_mangle]
pub extern "stdcall" fn TraceSQLGetStmtAttr(
    statement_handle: HStmt,
    attribute: StatementAttribute,
    value: Pointer,
    buffer_length: Integer,
    string_length: *mut Integer,
) -> SqlReturn {
    SqlReturn::SUCCESS
}

#[no_mangle]
pub extern "stdcall" fn TraceSQLGetStmtAttrW(
    handle: HStmt,
    attribute: StatementAttribute,
    value_ptr: Pointer,
    buffer_length: Integer,
    string_length_ptr: *mut Integer,
) -> SqlReturn {
    SqlReturn::SUCCESS
}

#[no_mangle]
pub extern "stdcall" fn TraceSQLGetTypeInfo(
    statement_handle: HStmt,
    data_type: SqlDataType,
) -> SqlReturn {
    SqlReturn::SUCCESS
}

#[no_mangle]
pub extern "stdcall" fn TraceSQLMoreResults(statement_handle: HStmt) -> SqlReturn {
    SqlReturn::SUCCESS
}

#[no_mangle]
pub extern "stdcall" fn TraceSQLNumParams(
    statement_handle: HStmt,
    parameter_count_ptr: *mut SmallInt,
) -> SqlReturn {
    SqlReturn::SUCCESS
}

#[no_mangle]
pub extern "stdcall" fn TraceSQLNumResultCols(
    statement_handle: HStmt,
    column_count_ptr: *mut SmallInt,
) -> SqlReturn {
    SqlReturn::SUCCESS
}

#[no_mangle]
pub extern "stdcall" fn TraceSQLParamData(statement_handle: HStmt, value_out: *mut Pointer) -> SqlReturn {
    SqlReturn::SUCCESS
}

#[no_mangle]
pub extern "stdcall" fn TraceSQLPrepare(
    statement_handle: HStmt,
    statement_text: *const Char,
    text_length: Integer,
) -> SqlReturn {
    SqlReturn::SUCCESS
}

#[no_mangle]
pub extern "stdcall" fn TraceSQLPrepareW(
    statement_handle: HStmt,
    statement_text: *const WChar,
    text_length: Integer,
) -> SqlReturn {
    SqlReturn::SUCCESS
}

#[no_mangle]
pub extern "stdcall" fn TraceSQLRowCount(statement_handle: HStmt, row_count: *mut Len) -> SqlReturn {
    SqlReturn::SUCCESS
}

#[no_mangle]
pub extern "stdcall" fn TraceSQLSetConnectAttr(
    hdbc: HDbc,
    attr: ConnectionAttribute,
    value: Pointer,
    str_length: Integer,
) -> SqlReturn {
    SqlReturn::SUCCESS
}

#[no_mangle]
pub extern "stdcall" fn TraceSQLSetConnectAttrW(
    hdbc: HDbc,
    attr: ConnectionAttribute,
    value: Pointer,
    str_length: Integer,
) -> SqlReturn {
    SqlReturn::SUCCESS
}

#[no_mangle]
pub extern "stdcall" fn TraceSQLSetDescField(
    description_handle: HDesc,
    rec_number: SmallInt,
    field_identifier: Desc,
    value: Pointer,
    buffer_length: Integer,
) -> SqlReturn {
    SqlReturn::SUCCESS
}

#[no_mangle]
pub extern "stdcall" fn TraceSQLSetDescFieldW(
    description_handle: HDesc,
    rec_number: SmallInt,
    field_identifier: Desc,
    value: Pointer,
    buffer_length: Integer,
) -> SqlReturn {
    SqlReturn::SUCCESS
}

#[no_mangle]
pub extern "stdcall" fn TraceSQLSetEnvAttr(
    environment_handle: HEnv,
    attribute: EnvironmentAttribute,
    value: Pointer,
    string_length: Integer,
) -> SqlReturn {
    SqlReturn::SUCCESS
}

#[no_mangle]
pub extern "stdcall" fn TraceSQLSetPos(
    statement_handle: HStmt,
    row_number: SetPosIRow,
    operation: Operation,
    lock_type: Lock,
) -> SqlReturn {
    SqlReturn::SUCCESS
}

#[no_mangle]
pub extern "stdcall" fn TraceSQLSetStmtAttr(
    statement_handle: HStmt,
    attr: StatementAttribute,
    value: Pointer,
    str_length: Integer,
) -> SqlReturn {
    SqlReturn::SUCCESS
}

#[no_mangle]
pub extern "stdcall" fn TraceSQLSetStmtAttrW(
    statement_handle: HStmt,
    attr: StatementAttribute,
    value: Pointer,
    str_length: Integer,
) -> SqlReturn {
    SqlReturn::SUCCESS
}

#[no_mangle]
pub extern "stdcall" fn TraceSQLTables(
    statement_handle: HStmt,
    catalog_name: *const Char,
    name_length_1: SmallInt,
    schema_name: *const Char,
    name_length_2: SmallInt,
    table_name: *const Char,
    name_length_3: SmallInt,
    table_type: *const Char,
    name_length_4: SmallInt,
) -> SqlReturn {
    SqlReturn::SUCCESS
}

#[no_mangle]
pub extern "stdcall" fn TraceSQLTablesW(
    statement_handle: HStmt,
    catalog_name: *const WChar,
    name_length_1: SmallInt,
    schema_name: *const WChar,
    name_length_2: SmallInt,
    table_name: *const WChar,
    name_length_3: SmallInt,
    table_type: *const WChar,
    name_length_4: SmallInt,
) -> SqlReturn {
    SqlReturn::SUCCESS
}

#[no_mangle]
pub extern "stdcall" fn TraceVersion() -> DWORD {
    // This should align with the ODBC version:
    // https://github.com/microsoft/ODBC-Specification/blob/4dda95986bda5d3b55d7749315d3e5a0951c1e50/Windows/inc/sqlext.h#L2353
    1000
}

fn print_to_log(str: &str) {
    let mut data = GLOBAL_DATA.lock().unwrap();
    if let Some(file) = data.file.as_mut() {
        file.write_all(str.as_bytes()).unwrap();
    }

}

/// Convert a LPWSTR to a String. This function assumes the LPWSTR is null-terminated.
/// Not all LPWSTRs are null-terminated. The caller must verify the LPWSTR is null terminated.
fn from_lpwstr(string: LPWSTR) -> Result<String, ()> {
    unsafe {
        U16CString::from_ptr_str(string).to_string().map_err(|_| ())
    }
}

/// Convert a *const WChar to a String. This function assumes the *const WChar is null-terminated.
fn from_wchar(string: *const WChar, length: usize) -> Result<String, ()> {
    unsafe {
        let slice = slice::from_raw_parts(string, length);
        U16CString::from_ptr(string, length).map_err(|_| ())?.to_string().map_err(|_| ())
    }
}
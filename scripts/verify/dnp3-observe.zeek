## Verification observer for decoded DNP3 messages. Run only over offline PCAPs.
## Unlike dnp3.log, retain every header, direction and per-message detail.
## Load ICSNPP-DNP3 first for its authoritative object/control label tables.

module SubstationDnp3;

export {
    redef enum Log::ID += { LOG };
    type Observation: record {
        id: conn_id &log;
        message: count &log;
        kind: string &log;
        is_orig: bool &log;
        func_code: count &log;
        func_name: string &log;
        iin: count &log &optional;
        object_type: string &log &optional;
        object_count: count &log &optional;
        range_low: count &log &optional;
        range_high: count &log &optional;
        block_type: string &log &optional;
        index_number: count &log &optional;
        trip_control_code: string &log &optional;
        operation_type: string &log &optional;
        clear_bit: bool &log &optional;
        execute_count: count &log &optional;
        on_time: count &log &optional;
        off_time: count &log &optional;
        status_code: string &log &optional;
    };
}

redef record connection += {
    substation_dnp3_message: count &default=0;
    substation_dnp3_header: Observation &optional;
    substation_dnp3_index: count &optional;
};

event zeek_init() &priority=5
    {
    Log::create_stream(LOG, [$columns=Observation, $path="substation_dnp3"]);
    }

function header(c: connection, is_orig: bool, fc: count): Observation
    {
    ++c$substation_dnp3_message;
    delete c$substation_dnp3_index;
    return [$id=c$id, $message=c$substation_dnp3_message, $kind="header",
            $is_orig=is_orig, $func_code=fc, $func_name=DNP3::function_codes[fc]];
    }

event dnp3_application_request_header(c: connection, is_orig: bool,
                                      application_control: count, fc: count)
    {
    c$substation_dnp3_header = header(c, is_orig, fc);
    Log::write(LOG, c$substation_dnp3_header);
    }

event dnp3_application_response_header(c: connection, is_orig: bool,
                                       application_control: count, fc: count, iin: count)
    {
    c$substation_dnp3_header = header(c, is_orig, fc);
    c$substation_dnp3_header$iin = iin;
    Log::write(LOG, c$substation_dnp3_header);
    }

function detail(c: connection, is_orig: bool, kind: string): Observation
    {
    if ( ! c?$substation_dnp3_header || c$substation_dnp3_header$is_orig != is_orig )
        Reporter::fatal("DNP3 detail without a matching header");
    local rec = copy(c$substation_dnp3_header);
    rec$kind = kind;
    return rec;
    }

event dnp3_object_header(c: connection, is_orig: bool, obj_type: count,
                         qua_field: count, number: count, rf_low: count, rf_high: count)
    {
    # CROB headers are represented by their decoded control block below.
    if ( obj_type == 0x0c01 )
        return;
    local rec = detail(c, is_orig, "objects");
    rec$object_type = DNP3_Extended::dnp3_objects[obj_type];
    if ( ! is_orig )
        {
        rec$object_count = number;
        rec$range_low = rf_low;
        rec$range_high = rf_high;
        }
    Log::write(LOG, rec);
    }

event dnp3_object_prefix(c: connection, is_orig: bool, prefix_value: count)
    {
    c$substation_dnp3_index = prefix_value;
    }

event dnp3_crob(c: connection, is_orig: bool, control_code: count, count8: count,
                on_time: count, off_time: count, status_code: count)
    {
    local rec = detail(c, is_orig, "control");
    rec$block_type = "Control Relay Output Block";
    if ( c?$substation_dnp3_index )
        rec$index_number = c$substation_dnp3_index;
    rec$trip_control_code = DNP3_Extended::control_block_trip_code[(control_code & 0xc0) / 64];
    rec$operation_type = DNP3_Extended::control_block_operation_type[control_code & 0x0f];
    rec$clear_bit = (control_code & 0x20) != 0;
    rec$execute_count = count8;
    rec$on_time = on_time;
    rec$off_time = off_time;
    if ( rec$func_name == "RESPONSE" )
        rec$status_code = DNP3_Extended::control_block_status_codes[status_code];
    Log::write(LOG, rec);
    }

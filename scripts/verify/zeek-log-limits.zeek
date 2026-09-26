## Tier-2 verification only: log complete value vectors.
##
## Zeek truncates logged containers at 100 elements per field and 500 per record
## by default (Zeek 8.2), below the Modbus protocol maxima of 2,000 bits and 125
## registers per read. Truncated vectors would make the field comparison report
## false differences, so every verification run loads these limits.
redef Log::default_max_field_container_elements = 2000;
redef Log::default_max_total_container_elements = 4000;

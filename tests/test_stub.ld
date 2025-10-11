SECTIONS
{
    .data : {
        _binary_complete_unpacking_stub_compiled_bin_start = .;
        *(.data)
        _binary_complete_unpacking_stub_compiled_bin_end = .;
    }
}
/// Helper module for constructing deterministic synthetic PE and binary fixtures for tests.

pub fn build_mock_pe(
    sections: &[(&str, u32, &[u8])], // (name, characteristics, data)
    imported_dlls: &[(&str, &[&str])], // (dll_name, [funcs])
) -> Vec<u8> {
    let mut pe = vec![0u8; 1024];

    // DOS Header
    pe[0] = b'M';
    pe[1] = b'Z';
    // e_lfanew at 0x3C -> 0x80
    pe[0x3C] = 0x80;

    // NT Headers at 0x80
    let nt_offset = 0x80;
    pe[nt_offset..nt_offset + 4].copy_from_slice(b"PE\0\0");

    // COFF File Header at 0x84
    let coff_offset = nt_offset + 4;
    pe[coff_offset..coff_offset + 2].copy_from_slice(&0x8664u16.to_le_bytes()); // x86_64
    let num_sections = sections.len() as u16;
    pe[coff_offset + 2..coff_offset + 4].copy_from_slice(&num_sections.to_le_bytes());
    pe[coff_offset + 16..coff_offset + 18].copy_from_slice(&240u16.to_le_bytes()); // size of optional header
    pe[coff_offset + 18..coff_offset + 20].copy_from_slice(&0x0002u16.to_le_bytes()); // executable

    // Optional Header (PE32+) at 0x98
    let opt_offset = coff_offset + 20;
    pe[opt_offset..opt_offset + 2].copy_from_slice(&0x020Bu16.to_le_bytes()); // PE32+
    pe[opt_offset + 16..opt_offset + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // AddressOfEntryPoint
    pe[opt_offset + 24..opt_offset + 32].copy_from_slice(&0x0000000140000000u64.to_le_bytes()); // ImageBase

    // Data Directory for Import Table at opt_offset + 112 + 8 (index 1)
    let import_dir_offset = opt_offset + 112 + 8;
    // We will place import table at RVA 0x2000
    if !imported_dlls.is_empty() {
        pe[import_dir_offset..import_dir_offset + 4].copy_from_slice(&0x2000u32.to_le_bytes());
        pe[import_dir_offset + 4..import_dir_offset + 8].copy_from_slice(&100u32.to_le_bytes());
    }

    // Section Headers start at opt_offset + 240
    let sec_table_offset = opt_offset + 240;
    let mut current_rva = 0x1000u32;
    let mut current_file_offset = 0x400u32;

    for (i, (name, chars, sec_data)) in sections.iter().enumerate() {
        let entry_offset = sec_table_offset + (i * 40);
        let mut name_bytes = [0u8; 8];
        let copy_len = name.as_bytes().len().min(8);
        name_bytes[..copy_len].copy_from_slice(&name.as_bytes()[..copy_len]);
        pe[entry_offset..entry_offset + 8].copy_from_slice(&name_bytes);

        let raw_size = (sec_data.len() as u32).max(512);
        let virt_size = raw_size;

        pe[entry_offset + 8..entry_offset + 12].copy_from_slice(&virt_size.to_le_bytes());
        pe[entry_offset + 12..entry_offset + 16].copy_from_slice(&current_rva.to_le_bytes());
        pe[entry_offset + 16..entry_offset + 20].copy_from_slice(&raw_size.to_le_bytes());
        pe[entry_offset + 20..entry_offset + 24].copy_from_slice(&current_file_offset.to_le_bytes());
        pe[entry_offset + 36..entry_offset + 40].copy_from_slice(&chars.to_le_bytes());

        // Append section data to PE
        if pe.len() < (current_file_offset as usize + raw_size as usize) {
            pe.resize(current_file_offset as usize + raw_size as usize, 0);
        }
        pe[current_file_offset as usize..current_file_offset as usize + sec_data.len()]
            .copy_from_slice(sec_data);

        current_rva += (virt_size + 0xFFF) & !0xFFF;
        current_file_offset += (raw_size + 0x1FF) & !0x1FF;
    }

    pe
}

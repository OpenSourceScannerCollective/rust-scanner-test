
pub fn calc_base64_padding(str_len: usize) -> u8 {
    match str_len % 4 {
        0 => 0,
        1 => 3,
        2 => 2,
        3 => 1,
        _ => unreachable!(),
    }
}
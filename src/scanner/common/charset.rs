use std::ops::RangeInclusive;

pub const ASCII_ALPHA_LOWER: RangeInclusive<char> = 'a'..='z';
pub const ASCII_ALPHA_UPPER: RangeInclusive<char> = 'A'..='Z';
pub const ASCII_NUM: RangeInclusive<char> = '0'..='9';
pub const ASCII_ALPHA: (RangeInclusive<char>, RangeInclusive<char>) =
    (ASCII_ALPHA_LOWER, ASCII_ALPHA_UPPER);
pub const ASCII_ALPHA_NUM: (
    RangeInclusive<char>,
    RangeInclusive<char>,
    RangeInclusive<char>,
) = (ASCII_NUM, ASCII_ALPHA_LOWER, ASCII_ALPHA_UPPER);
pub const ASCII_ALPHA_NUM_UPPER: (RangeInclusive<char>, RangeInclusive<char>) =
    (ASCII_NUM, ASCII_ALPHA_UPPER);
pub const ASCII_ALPHA_NUM_LOWER: (RangeInclusive<char>, RangeInclusive<char>) =
    (ASCII_NUM, ASCII_ALPHA_LOWER);
pub const ASCII_SYMBOL: (
    RangeInclusive<char>,
    RangeInclusive<char>,
    RangeInclusive<char>,
    RangeInclusive<char>,
) = ('!'..='/', ':'..='@', '['..='`', '{'..='~');
pub const ASCII_ALPHA_SYMBOL_WS: (
    (
        RangeInclusive<char>,
        RangeInclusive<char>,
        RangeInclusive<char>,
    ),
    (
        RangeInclusive<char>,
        RangeInclusive<char>,
        RangeInclusive<char>,
        RangeInclusive<char>,
    ),
    (RangeInclusive<char>, char),
) = (ASCII_ALPHA_NUM, ASCII_SYMBOL, ASCII_WHITESPACE);
pub const ASCII_ALPHA_SYMBOL: (
    (
        RangeInclusive<char>,
        RangeInclusive<char>,
        RangeInclusive<char>,
    ),
    (
        RangeInclusive<char>,
        RangeInclusive<char>,
        RangeInclusive<char>,
        RangeInclusive<char>,
    ),
) = (ASCII_ALPHA_NUM, ASCII_SYMBOL);
pub const ASCII_ALPHA_SYMBOL_UPPER: (
    (
        RangeInclusive<char>,
        RangeInclusive<char>,
        RangeInclusive<char>,
    ),
    (
        RangeInclusive<char>,
        RangeInclusive<char>,
        RangeInclusive<char>,
        RangeInclusive<char>,
    ),
) = (ASCII_ALPHA_NUM, ASCII_SYMBOL);
pub const ASCII_ALPHA_SYMBOL_WS_UPPER: (
    (RangeInclusive<char>, RangeInclusive<char>),
    (
        RangeInclusive<char>,
        RangeInclusive<char>,
        RangeInclusive<char>,
        RangeInclusive<char>,
    ),
    (RangeInclusive<char>, char),
) = (ASCII_ALPHA_NUM_UPPER, ASCII_SYMBOL, ASCII_WHITESPACE);
pub const ASCII_ALPHA_SYMBOL_WS_LOWER: (
    (RangeInclusive<char>, RangeInclusive<char>),
    (
        RangeInclusive<char>,
        RangeInclusive<char>,
        RangeInclusive<char>,
        RangeInclusive<char>,
    ),
    (RangeInclusive<char>, char),
) = (ASCII_ALPHA_NUM_LOWER, ASCII_SYMBOL, ASCII_WHITESPACE);
pub const ASCII_PRINTABLE: RangeInclusive<char> = '!'..='~';
pub const BASE16_LOWER: RangeInclusive<char> = 'a'..='f';
pub const BASE16_UPPER: RangeInclusive<char> = 'A'..='F';
pub const BASE16: (
    RangeInclusive<char>,
    RangeInclusive<char>,
    RangeInclusive<char>,
) = (ASCII_NUM, BASE16_LOWER, BASE16_UPPER);

pub const BASE64_SYMBOL: (char, char) = ('+', '/');
pub const BASE64: (
    (
        RangeInclusive<char>,
        RangeInclusive<char>,
        RangeInclusive<char>,
    ),
    (char, char),
) = (ASCII_ALPHA_NUM, BASE64_SYMBOL);
pub const BASE64_SYMBOL_PADDING: char = '=';
pub const BASE64_WITH_PADDING: (
    (
        RangeInclusive<char>,
        RangeInclusive<char>,
        RangeInclusive<char>,
    ),
    (char, char),
    char,
) = (ASCII_ALPHA_NUM, BASE64_SYMBOL, BASE64_SYMBOL_PADDING);
pub const ASCII_WHITESPACE: (RangeInclusive<char>, char) = (
    '\u{0009}'..='\u{000D}', // Control characters (tab, line feed, vertical tab,
    // form feed, carriage return)
    '\u{0020}', // Space
);
pub const UNICODE_WHITESPACE: (
    (RangeInclusive<char>, char),
    char,
    char,
    char,
    RangeInclusive<char>,
    RangeInclusive<char>,
    char,
    char,
    char,
) = (
    ASCII_WHITESPACE,
    '\u{0085}',              // Next Line
    '\u{00A0}',              // No-Break Space
    '\u{1680}',              // Ogham Space Mark
    '\u{2000}'..='\u{200A}', // En Quad to Hair Space
    '\u{2028}'..='\u{2029}', // Line Separator and Paragraph Separator
    '\u{202F}',              // Narrow No-Break Space
    '\u{205F}',              // Medium Mathematical Space
    '\u{3000}',              // Ideographic Space
);
pub const BASE64_WS: (
    (
        (
            RangeInclusive<char>,
            RangeInclusive<char>,
            RangeInclusive<char>,
        ),
        (char, char),
    ),
    (RangeInclusive<char>, char),
) = (BASE64, ASCII_WHITESPACE);
pub const BASE64_WITH_PADDING_WS: (
    (
        (
            RangeInclusive<char>,
            RangeInclusive<char>,
            RangeInclusive<char>,
        ),
        (char, char),
        char,
    ),
    (RangeInclusive<char>, char),
) = (BASE64_WITH_PADDING, ASCII_WHITESPACE);
pub const URL_CHARS: RangeInclusive<char> = '!'..='~';

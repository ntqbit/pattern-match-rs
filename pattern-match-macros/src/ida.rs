#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum IdaConvertionError {
    #[error("invalid byte digit")]
    InvalidByteDigit,
    #[error("not all bytes have length of 2")]
    InvalidByteLength,
}

fn ida_half_to_data(s: char) -> Result<(u8, u8), IdaConvertionError> {
    if s == '?' {
        Ok((0, 0))
    } else if let Some(digit) = s.to_digit(16) {
        Ok((digit as u8, 0xF))
    } else {
        Err(IdaConvertionError::InvalidByteDigit)
    }
}

pub fn parse_ida_pattern(pattern: &str) -> Result<Vec<(u8, u8)>, IdaConvertionError> {
    pattern
        .split(' ')
        .into_iter()
        .map(|x| {
            if x.len() != 2 {
                return Err(IdaConvertionError::InvalidByteLength);
            }

            let chrs: Vec<char> = x.chars().collect();
            let a = ida_half_to_data(chrs[0])?;
            let b = ida_half_to_data(chrs[1])?;

            Ok((a.0 << 4 | b.0, a.1 << 4 | b.1))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{parse_ida_pattern, IdaConvertionError};

    #[test]
    fn ida_pattern_to_pairs_test() {
        assert!(matches!(
            parse_ida_pattern("asd"),
            Err(IdaConvertionError::InvalidByteLength)
        ));
        assert!(matches!(
            parse_ida_pattern("as"),
            Err(IdaConvertionError::InvalidByteDigit)
        ));
        assert!(matches!(
            parse_ida_pattern("7"),
            Err(IdaConvertionError::InvalidByteLength)
        ));
        assert!(matches!(
            parse_ida_pattern("777"),
            Err(IdaConvertionError::InvalidByteLength)
        ));
        assert!(matches!(
            parse_ida_pattern(" 7"),
            Err(IdaConvertionError::InvalidByteLength)
        ));
        assert!(matches!(
            parse_ida_pattern("7 "),
            Err(IdaConvertionError::InvalidByteLength)
        ));
        assert!(matches!(
            parse_ida_pattern("77  88"),
            Err(IdaConvertionError::InvalidByteLength)
        ));
        assert!(matches!(
            parse_ida_pattern("77 8 99"),
            Err(IdaConvertionError::InvalidByteLength)
        ));
        assert!(matches!(
            parse_ida_pattern("77 88 99 "),
            Err(IdaConvertionError::InvalidByteLength)
        ));
        assert!(matches!(
            parse_ida_pattern(" 77 88 99 "),
            Err(IdaConvertionError::InvalidByteLength)
        ));
        assert!(matches!(
            parse_ida_pattern(" 77 88 99"),
            Err(IdaConvertionError::InvalidByteLength)
        ));
        assert!(matches!(
            parse_ida_pattern("77 88 9? "),
            Err(IdaConvertionError::InvalidByteLength)
        ));
        assert!(matches!(
            parse_ida_pattern("77 88 99 ?"),
            Err(IdaConvertionError::InvalidByteLength)
        ));

        assert_eq!(
            parse_ida_pattern("77 88 99"),
            Ok(vec![(0x77, 0xFF), (0x88, 0xFF), (0x99, 0xFF)])
        );

        assert_eq!(
            parse_ida_pattern("77 8? 99"),
            Ok(vec![(0x77, 0xFF), (0x80, 0xF0), (0x99, 0xFF)])
        );

        assert_eq!(
            parse_ida_pattern("77 ?? 99"),
            Ok(vec![(0x77, 0xFF), (0x00, 0x00), (0x99, 0xFF)])
        );
    }
}

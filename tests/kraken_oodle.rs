//! Independent encoder oracle using the game's Oodle DLL, not kraken.dll.
#![allow(unsafe_code, reason = "test-only FFI to the independent Oodle oracle")]

use ghostline_red::kraken;
use libloading::Library;
use std::env;

type Decompress = unsafe extern "system" fn(
    *const u8,
    i64,
    *mut u8,
    i64,
    i32,
    i32,
    i32,
    *mut u8,
    i64,
    *mut u8,
    *mut u8,
    *mut u8,
    i64,
    i32,
) -> i64;

#[test]
#[ignore = "requires OODLE_DLL pointing to the game's oo2ext_7_win64.dll"]
fn oodle_decodes_encoder_at_chunk_and_block_boundaries() {
    let path = env::var_os("OODLE_DLL").expect("set OODLE_DLL to the game's Oodle DLL");
    // SAFETY: The caller supplies the trusted game library, kept live while
    // its documented OodleLZ_Decompress ABI is called below.
    let library = unsafe { Library::new(path).unwrap() };
    // SAFETY: Signature matches WolvenKit's OodleLib.DecompressDelegate.
    let decompress = unsafe { library.get::<Decompress>(b"OodleLZ_Decompress\0").unwrap() };
    for size in [
        256, 288, 512, 131_071, 131_072, 131_073, 262_143, 262_144, 262_145, 262_656, 786_449,
    ] {
        for period in [8, 17, 97, 4_093] {
            let mut state = 0x243f_6a88_u32;
            let seed: Vec<u8> = (0..period)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 17;
                    state ^= state << 5;
                    state.to_le_bytes()[0]
                })
                .collect();
            let payload: Vec<u8> = seed.iter().copied().cycle().take(size).collect();
            assert_oodle_round_trip(
                &decompress,
                &payload,
                &format!("size {size}, period {period}"),
            );
        }
    }
    // Vary offsets and short matches rather than testing periodic data alone.
    let mut state = 0x85a3_08d3_u32;
    let mut payload = Vec::new();
    for index in 0..90_000_usize {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        payload.push(state.to_le_bytes()[0]);
        if index > 64 && index % 11 == 0 {
            let start = payload.len() - 64;
            payload.extend_from_within(start..start + 8);
        }
    }
    assert_oodle_round_trip(&decompress, &payload, "mixed short matches");
    for alphabet in [1_u8, 2, 5, 64, 255] {
        let mut state = 0x510e_527f_u32;
        let payload: Vec<u8> = (0..786_449)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state.to_le_bytes()[0] % alphabet
            })
            .collect();
        assert_oodle_round_trip(&decompress, &payload, &format!("alphabet {alphabet}"));
    }
    let mut state = 0x1319_8a2e_u32;
    let mut mixed: Vec<u8> = (0..262_144)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state.to_le_bytes()[0]
        })
        .collect();
    mixed.extend_from_slice(&vec![0x5a; 262_144]);
    mixed.extend_from_within(..262_144);
    assert_oodle_round_trip(&decompress, &mixed, "raw and memset block transitions");
}

fn assert_oodle_round_trip(decompress: &Decompress, payload: &[u8], case: &str) {
    let encoded = kraken::encode(payload);
    let encoded_size = i64::try_from(encoded.len()).unwrap();
    let mut guarded = encoded;
    guarded.resize(guarded.len() + 64, 0);
    let mut decoded = vec![0_u8; payload.len() + 64];
    // SAFETY: Input/output are live non-overlapping buffers with speculative
    // access guards; logical sizes are exact. FuzzSafe=Yes, ThreadPhase=All.
    let actual = unsafe {
        decompress(
            guarded.as_ptr(),
            encoded_size,
            decoded.as_mut_ptr(),
            i64::try_from(payload.len()).unwrap(),
            1,
            0,
            0,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
            3,
        )
    };
    assert_eq!(actual, i64::try_from(payload.len()).unwrap(), "{case}");
    assert_eq!(&decoded[..payload.len()], payload, "{case}");
}

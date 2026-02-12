#![no_std]
#![feature(alloc_error_handler)]

extern crate alloc;
use core::alloc::{GlobalAlloc, Layout};

struct Dummy;
#[global_allocator]
static ALLOCATOR: Dummy = Dummy;
unsafe impl GlobalAlloc for Dummy {
    unsafe fn alloc(&self, _layout: Layout) -> *mut u8 { core::ptr::null_mut() }
    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}
#[alloc_error_handler]
fn alloc_error(_layout: Layout) -> ! { loop {} }

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }

// Syscall Symbols
extern "C" {
    pub fn sol_log_(message: *const u8, len: u64);
    pub fn sol_log_64_(arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64);
    pub fn sol_set_return_data(data: *const u8, len: u64);
}

pub fn msg(message: &str) {
    unsafe { sol_log_(message.as_ptr(), message.len() as u64) };
}

pub mod solana_program {
    pub mod pubkey {
        #[repr(transparent)]
        #[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
        pub struct Pubkey(pub [u8; 32]);
        impl Pubkey {
             pub const fn new_from_array(addr: [u8; 32]) -> Self { Self(addr) }
             pub fn to_bytes(&self) -> [u8; 32] { self.0 }
             pub fn as_ref(&self) -> &[u8; 32] { &self.0 }
        }
        impl AsRef<[u8]> for Pubkey {
            fn as_ref(&self) -> &[u8] { &self.0 }
        }
    }
    pub mod program_error {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        #[repr(u64)]
        pub enum ProgramError {
            InvalidArgument = 1,
            InvalidInstructionData = 2,
            InvalidAccountData = 3,
            AccountBorrowFailed = 4,
            NotEnoughAccountKeys = 5,
            Custom(u32) = 0x100000000,
        }
        impl From<u32> for ProgramError {
            fn from(v: u32) -> Self { ProgramError::Custom(v) }
        }
    }
    pub mod account_info {
        use crate::solana_program::pubkey::Pubkey;
        use core::cell::RefCell;
        #[repr(C)]
        pub struct AccountInfo<'a> {
            pub key: &'a Pubkey,
            pub is_signer: bool,
            pub is_writable: bool,
            pub lamports: RefCell<&'a mut u64>,
            pub data: RefCell<&'a mut [u8]>,
            pub owner: &'a Pubkey,
            pub executable: bool,
            pub rent_epoch: u64,
        }
        impl<'a> AccountInfo<'a> {
            pub fn try_borrow_data(&self) -> Result<core::cell::Ref<'_, &mut [u8]>, ()> {
                Ok(self.data.borrow())
            }
            pub fn try_borrow_mut_data(&self) -> Result<core::cell::RefMut<'_, &mut [u8]>, ()> {
                Ok(self.data.borrow_mut())
            }
        }
    }
    pub mod sysvar {
        pub mod instructions {
            use crate::solana_program::pubkey::Pubkey;
            pub const ID: Pubkey = Pubkey::new_from_array([
                0x06, 0xa1, 0x07, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            ]);
            pub fn load_current_index(data: &[u8]) -> u16 {
                if data.len() < 2 { return 0; }
                u16::from_le_bytes([data[0], data[1]])
            }

            pub fn load_instruction_at_checked(
                index: usize,
                account_info: &crate::solana_program::account_info::AccountInfo,
            ) -> Result<crate::solana_program::instruction::Instruction, crate::solana_program::program_error::ProgramError> {
                let data = account_info.try_borrow_data().map_err(|_| crate::solana_program::program_error::ProgramError::AccountBorrowFailed)?;
                let mut slice = &data[..];
                
                // Helper to read u64
                let read_u64 = |input: &mut &[u8]| -> Result<u64, crate::solana_program::program_error::ProgramError> {
                    if input.len() < 8 { return Err(crate::solana_program::program_error::ProgramError::InvalidAccountData); }
                    let (bytes, rest) = input.split_at(8);
                    *input = rest;
                    Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
                };

                let num_ix = read_u64(&mut slice)?;
                if index as u64 >= num_ix {
                    return Err(crate::solana_program::program_error::ProgramError::InvalidArgument);
                }

                // Helper to skip instruction
                let mut skip_instruction = |input: &mut &[u8]| -> Result<(), crate::solana_program::program_error::ProgramError> {
                    if input.len() < 32 { return Err(crate::solana_program::program_error::ProgramError::InvalidAccountData); }
                    let (_, rest) = input.split_at(32); *input = rest; 
                    
                    let num_accounts = read_u64(input)?;
                    let accounts_len = num_accounts.checked_mul(34).ok_or(crate::solana_program::program_error::ProgramError::ArithmeticOverflow)?;
                    if input.len() < accounts_len as usize { return Err(crate::solana_program::program_error::ProgramError::InvalidAccountData); }
                    let (_, rest) = input.split_at(accounts_len as usize);
                    *input = rest;

                    let data_len = read_u64(input)?;
                    if input.len() < data_len as usize { return Err(crate::solana_program::program_error::ProgramError::InvalidAccountData); }
                    let (_, rest) = input.split_at(data_len as usize);
                    *input = rest;
                    Ok(())
                };

                for _ in 0..index {
                    skip_instruction(&mut slice)?;
                }

                // Read instruction
                let program_id_bytes = {
                    if slice.len() < 32 { return Err(crate::solana_program::program_error::ProgramError::InvalidAccountData); }
                    let (bytes, rest) = slice.split_at(32);
                    *slice = rest;
                    bytes
                };
                let program_id = crate::solana_program::pubkey::Pubkey::new_from_array(program_id_bytes.try_into().unwrap());
                
                let num_accounts = read_u64(&mut slice)?;
                let mut accounts = alloc::vec::Vec::with_capacity(num_accounts as usize);
                for _ in 0..num_accounts {
                        if slice.len() < 34 { return Err(crate::solana_program::program_error::ProgramError::InvalidAccountData); }
                        let (pubkey_bytes, rest) = slice.split_at(32);
                        let (is_signer_byte, rest) = rest.split_first().ok_or(crate::solana_program::program_error::ProgramError::InvalidAccountData)?;
                        let (is_writable_byte, rest) = rest.split_first().ok_or(crate::solana_program::program_error::ProgramError::InvalidAccountData)?;
                        *slice = rest;
                        
                        accounts.push(crate::solana_program::instruction::AccountMeta {
                            pubkey: crate::solana_program::pubkey::Pubkey::new_from_array(pubkey_bytes.try_into().unwrap()),
                            is_signer: *is_signer_byte != 0,
                            is_writable: *is_writable_byte != 0,
                        });
                }

                let data_len = read_u64(&mut slice)?;
                if slice.len() < data_len as usize { return Err(crate::solana_program::program_error::ProgramError::InvalidAccountData); }
                let (data_bytes, rest) = slice.split_at(data_len as usize);
                *slice = rest;

                Ok(crate::solana_program::instruction::Instruction {
                    program_id,
                    accounts,
                    data: data_bytes.to_vec(),
                })
            }
        }
        pub mod clock {
            use crate::solana_program::account_info::AccountInfo;
            pub struct Clock {
                pub slot: u64,
                pub epoch_start_timestamp: i64,
                pub epoch: u64,
                pub leader_schedule_epoch: u64,
                pub unix_timestamp: i64,
            }
            impl Clock {
                pub fn from_account_info(ai: &AccountInfo) -> Result<Self, crate::solana_program::program_error::ProgramError> {
                    let data = ai.try_borrow_data().map_err(|_| crate::solana_program::program_error::ProgramError::AccountBorrowFailed)?;
                    if data.len() < 40 { return Err(crate::solana_program::program_error::ProgramError::InvalidAccountData); }
                    Ok(Clock {
                        slot: u64::from_le_bytes(data[0..8].try_into().unwrap()),
                        epoch_start_timestamp: i64::from_le_bytes(data[8..16].try_into().unwrap()),
                        epoch: u64::from_le_bytes(data[16..24].try_into().unwrap()),
                        leader_schedule_epoch: u64::from_le_bytes(data[24..32].try_into().unwrap()),
                        unix_timestamp: i64::from_le_bytes(data[32..40].try_into().unwrap()),
                    })
                }
            }
        }
    }
    pub mod ed25519_program {
        use crate::solana_program::pubkey::Pubkey;
        pub const ID: Pubkey = Pubkey::new_from_array([0; 32]);
    }
    pub mod instruction {
        use crate::solana_program::pubkey::Pubkey;
        use alloc::vec::Vec;
        #[derive(Debug, PartialEq, Clone)]
        pub struct Instruction {
            pub program_id: Pubkey,
            pub accounts: Vec<AccountMeta>,
            pub data: Vec<u8>,
        }
        #[derive(Debug, PartialEq, Clone)]
        pub struct AccountMeta {
            pub pubkey: Pubkey,
            pub is_signer: bool,
            pub is_writable: bool,
        }
    }
}

// Minimal SPL Token implementation for SBF
pub mod spl_token {
    use crate::solana_program::pubkey::Pubkey;
    use crate::solana_program::program_error::ProgramError;

    pub const ID: Pubkey = Pubkey::new_from_array([
        6, 221, 246, 225, 215, 101, 161, 147, 217, 203, 225, 70, 206, 235, 121, 172, 28, 180, 133, 237,
        95, 91, 55, 145, 58, 140, 245, 133, 126, 255, 0, 169,
    ]);

    pub fn transfer(
        token_program_id: &Pubkey,
        source: &Pubkey,
        destination: &Pubkey,
        authority: &Pubkey,
        signer_pubkeys: &[&Pubkey],
        amount: u64,
    ) -> Result<crate::solana_program::instruction::Instruction, ProgramError> {
        let mut data = alloc::vec![3u8];
        data.extend_from_slice(&amount.to_le_bytes());
        
        // We need Instruction and AccountMeta to be available
        // They are defined later in the file, but we need them here.
        // For simplicity in this self-contained file, we'll assume crate::solana_program has them
        // If not, we'll patch solana_program module above.
        
        let mut accounts = alloc::vec![
            crate::solana_program::instruction::AccountMeta { pubkey: *source, is_signer: false, is_writable: true },
            crate::solana_program::instruction::AccountMeta { pubkey: *destination, is_signer: false, is_writable: true },
            crate::solana_program::instruction::AccountMeta { pubkey: *authority, is_signer: true, is_writable: false },
        ];
        for signer in signer_pubkeys {
            accounts.push(crate::solana_program::instruction::AccountMeta { pubkey: **signer, is_signer: true, is_writable: false });
        }

        Ok(crate::solana_program::instruction::Instruction {
            program_id: *token_program_id,
            accounts,
            data,
        })
    }
}


pub mod bytemuck {
    pub trait Pod: Copy + 'static {}
    pub trait Zeroable {}
    impl Pod for u64 {}
    impl Zeroable for u64 {}
    impl Pod for u32 {}
    impl Zeroable for u32 {}
    impl Pod for i128 {}
    impl Zeroable for i128 {}
    impl Pod for u128 {}
    impl Zeroable for u128 {}
    impl Pod for u8 {}
    impl Zeroable for u8 {} 
    
    pub fn try_from_bytes<T: Pod>(bytes: &[u8]) -> Result<&T, ()> {
        if bytes.len() != core::mem::size_of::<T>() { return Err(()); }
        if (bytes.as_ptr() as usize) % core::mem::align_of::<T>() != 0 { return Err(()); }
        Ok(unsafe { &*(bytes.as_ptr() as *const T) })
    }
    pub fn try_from_bytes_mut<T: Pod>(bytes: &mut [u8]) -> Result<&mut T, ()> {
        if bytes.len() != core::mem::size_of::<T>() { return Err(()); }
        if (bytes.as_ptr() as usize) % core::mem::align_of::<T>() != 0 { return Err(()); }
        Ok(unsafe { &mut *(bytes.as_mut_ptr() as *mut T) })
    }
    pub fn from_bytes<T: Pod>(bytes: &[u8]) -> &T {
        try_from_bytes(bytes).unwrap()
    }
    pub fn from_bytes_mut<T: Pod>(bytes: &mut [u8]) -> &mut T {
        try_from_bytes_mut(bytes).unwrap()
    }
    pub fn bytes_of<T: Pod>(t: &T) -> &[u8] {
        unsafe { core::slice::from_raw_parts(t as *const T as *const u8, core::mem::size_of::<T>()) }
    }
    pub fn bytes_of_mut<T: Pod>(t: &mut T) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(t as *mut T as *mut u8, core::mem::size_of::<T>()) }
    }
    pub fn cast_slice_mut<A: Pod, B: Pod>(a: &mut [A]) -> &mut [B] {
        unsafe {
             let new_len = (a.len() * core::mem::size_of::<A>()) / core::mem::size_of::<B>();
             core::slice::from_raw_parts_mut(a.as_mut_ptr() as *mut B, new_len)
        }
    }
}

// Helper trait to replace copy_from_slice which might be missing in some no-std contexts or shadowed
pub trait SliceCopy {
    fn copy_from_slice(&mut self, src: &[u8]);
}
impl SliceCopy for [u8] {
    fn copy_from_slice(&mut self, src: &[u8]) {
        self.copy_from_slice(src);
    }
}

// Map standard names to internal names for ease of porting
pub use crate::solana_program::pubkey::Pubkey;
pub use crate::solana_program::program_error::ProgramError;
pub use crate::solana_program::account_info::AccountInfo;

#[macro_export]
macro_rules! declare_id {
    ($id:expr) => {
        pub const ID: crate::solana_program::pubkey::Pubkey = crate::solana_program::pubkey::Pubkey::new_from_array([0; 32]);
    };
}

// ... Append contents of combined_percolator.rs but with module fixes ...
// 1. mod constants
pub mod constants {
    use crate::state::{MarketConfig, SlabHeader};
    use core::mem::{align_of, size_of};
    use crate::percolator::RiskEngine;

    pub const MAGIC: u64 = 0x504552434f4c4154; // "PERCOLAT"
    pub const VERSION: u32 = 1;

    pub const HEADER_LEN: usize = size_of::<SlabHeader>();
    pub const CONFIG_LEN: usize = size_of::<MarketConfig>();
    pub const ENGINE_ALIGN: usize = align_of::<RiskEngine>();

    pub const fn align_up(x: usize, a: usize) -> usize {
        (x + (a - 1)) & !(a - 1)
    }

    pub const ENGINE_OFF: usize = align_up(HEADER_LEN + CONFIG_LEN, ENGINE_ALIGN);
    pub const ENGINE_LEN: usize = size_of::<RiskEngine>();
    pub const SLAB_LEN: usize = ENGINE_OFF + ENGINE_LEN;
    pub const MATCHER_ABI_VERSION: u32 = 1;
    pub const MATCHER_CONTEXT_PREFIX_LEN: usize = 64;
    pub const MATCHER_CONTEXT_LEN: usize = 320;
    pub const MATCHER_CALL_TAG: u8 = 0;
    pub const MATCHER_CALL_LEN: usize = 67;

    /// Sentinel value for permissionless crank (no caller account required)
    pub const CRANK_NO_CALLER: u16 = u16::MAX;

    /// Maximum allowed unit_scale for InitMarket.
    /// unit_scale=0 disables scaling (1:1 base tokens to units, dust=0 always).
    /// unit_scale=1..=1_000_000_000 enables scaling with dust tracking.
    pub const MAX_UNIT_SCALE: u32 = 1_000_000_000;

    // Default funding parameters (used at init_market, can be changed via update_config)
    pub const DEFAULT_FUNDING_HORIZON_SLOTS: u64 = 500; // ~4 min @ ~2 slots/sec
    pub const DEFAULT_FUNDING_K_BPS: u64 = 100; // 1.00x multiplier
    pub const DEFAULT_FUNDING_INV_SCALE_NOTIONAL_E6: u128 = 1_000_000_000_000; // Funding scale factor (e6 units)
    pub const DEFAULT_FUNDING_MAX_PREMIUM_BPS: i64 = 500; // cap premium at 5.00%
    pub const DEFAULT_FUNDING_MAX_BPS_PER_SLOT: i64 = 5; // cap per-slot funding
    pub const DEFAULT_HYPERP_PRICE_CAP_E2BPS: u64 = 10_000; // 1% per slot max price change for Hyperp

    // Matcher call ABI offsets (67-byte layout)
    // byte 0: tag (u8)
    // 1..9: req_id (u64)
    // 9..11: lp_idx (u16)
    // 11..19: lp_account_id (u64)
    // 19..27: oracle_price_e6 (u64)
    // 27..43: req_size (i128)
    // 43..67: reserved (must be zero)
    pub const CALL_OFF_TAG: usize = 0;
    pub const CALL_OFF_REQ_ID: usize = 1;
    pub const CALL_OFF_LP_IDX: usize = 9;
    pub const CALL_OFF_LP_ACCOUNT_ID: usize = 11;
    pub const CALL_OFF_ORACLE_PRICE: usize = 19;
    pub const CALL_OFF_REQ_SIZE: usize = 27;
    pub const CALL_OFF_PADDING: usize = 43;

    // Matcher return ABI offsets (64-byte prefix)
    pub const RET_OFF_ABI_VERSION: usize = 0;
    pub const RET_OFF_FLAGS: usize = 4;
    pub const RET_OFF_EXEC_PRICE: usize = 8;
    pub const RET_OFF_EXEC_SIZE: usize = 16;
    pub const RET_OFF_REQ_ID: usize = 32;
    pub const RET_OFF_LP_ACCOUNT_ID: usize = 40;
    pub const RET_OFF_ORACLE_PRICE: usize = 48;
    pub const RET_OFF_RESERVED: usize = 56;

    // Default threshold parameters (used at init_market, can be changed via update_config)
    pub const DEFAULT_THRESH_FLOOR: u128 = 0;
    pub const DEFAULT_THRESH_RISK_BPS: u64 = 50; // 0.50%
    pub const DEFAULT_THRESH_UPDATE_INTERVAL_SLOTS: u64 = 10;
    pub const DEFAULT_THRESH_STEP_BPS: u64 = 500; // 5% max step
    pub const DEFAULT_THRESH_ALPHA_BPS: u64 = 1000; // 10% EWMA
    pub const DEFAULT_THRESH_MIN: u128 = 0;
    pub const DEFAULT_THRESH_MAX: u128 = 10_000_000_000_000_000_000u128;
    pub const DEFAULT_THRESH_MIN_STEP: u128 = 1;
}

// 1b. Risk metric helpers (pure functions for anti-DoS threshold calculation)

/// LP risk state: (sum_abs, max_abs) over all LP positions.
/// LP aggregate risk state for O(1) risk delta checks.
/// Uses engine's maintained aggregates instead of scanning.
pub struct LpRiskState {
    pub sum_abs: u128,
    pub max_abs: u128,
}

impl LpRiskState {
    /// Get LP aggregate risk state from engine's maintained fields. O(1).
    #[inline]
    pub fn compute(engine: &crate::percolator::RiskEngine) -> Self {
        Self {
            sum_abs: engine.lp_sum_abs.get(),
            max_abs: engine.lp_max_abs.get(),
        }
    }

    /// Current risk metric: max_concentration + sum_abs/8
    #[inline]
    pub fn risk(&self) -> u128 {
        self.max_abs.saturating_add(self.sum_abs / 8)
    }

    /// O(1) check: would applying delta to LP at lp_idx increase system risk?
    /// delta is the LP's position change (negative of user's trade size).
    /// Conservative: when LP was max and shrinks, we keep max_abs (overestimates risk, safe).
    #[inline]
    pub fn would_increase_risk(&self, old_lp_pos: i128, delta: i128) -> bool {
        let old_lp_abs = old_lp_pos.unsigned_abs();
        let new_lp_pos = old_lp_pos.saturating_add(delta);
        let new_lp_abs = new_lp_pos.unsigned_abs();

        // Guard: old_lp_abs must be part of sum_abs (caller must use same engine snapshot)
        #[cfg(debug_assertions)]
        debug_assert!(
            self.sum_abs >= old_lp_abs,
            "old_lp_abs not in sum_abs - wrong engine snapshot?"
        );

        // Update sum_abs in O(1)
        let new_sum_abs = self
            .sum_abs
            .saturating_sub(old_lp_abs)
            .saturating_add(new_lp_abs);

        // Update max_abs in O(1) (conservative when LP was max and shrinks)
        let new_max_abs = if new_lp_abs >= self.max_abs {
            // LP becomes new max (or ties)
            new_lp_abs
        } else if old_lp_abs == self.max_abs && new_lp_abs < old_lp_abs {
            // LP was max and shrunk - we don't know second-largest without scan.
            // Conservative: keep old max (overestimates risk, which is safe for gating).
            self.max_abs
        } else {
            // LP wasn't max, stays not max
            self.max_abs
        };

        let old_risk = self.risk();
        let new_risk = new_max_abs.saturating_add(new_sum_abs / 8);
        new_risk > old_risk
    }
}

/// Compute system risk units for threshold calculation. O(1).
/// Uses engine's maintained LP aggregates instead of scanning.
#[inline]
pub fn compute_system_risk_units(engine: &crate::percolator::RiskEngine) -> u128 {
    LpRiskState::compute(engine).risk()
}

/// Compute net LP position for inventory-based funding. O(1).
/// Uses engine's maintained net_lp_pos instead of scanning.
#[inline]
fn compute_net_lp_pos(engine: &crate::percolator::RiskEngine) -> i128 {
    engine.net_lp_pos.get()
}

/// Compute inventory-based funding rate (bps per slot).
///
/// Engine convention:
///   funding_rate_bps_per_slot > 0 => longs pay shorts
///   (because pnl -= position * ΔF, ΔF>0 when rate>0)
///
/// Policy: rate sign follows LP inventory sign to push net_lp_pos toward 0.
///   - If LP net long (net_lp_pos > 0), rate > 0 => longs pay => discourages longs => pushes inventory toward 0.
///   - If LP net short (net_lp_pos < 0), rate < 0 => shorts pay => discourages shorts => pushes inventory toward 0.
pub fn compute_inventory_funding_bps_per_slot(
    net_lp_pos: i128,
    price_e6: u64,
    funding_horizon_slots: u64,
    funding_k_bps: u64,
    funding_inv_scale_notional_e6: u128,
    funding_max_premium_bps: i64,
    funding_max_bps_per_slot: i64,
) -> i64 {
    if net_lp_pos == 0 || price_e6 == 0 || funding_horizon_slots == 0 {
        return 0;
    }

    let abs_pos: u128 = net_lp_pos.unsigned_abs();
    let notional_e6: u128 = abs_pos.saturating_mul(price_e6 as u128) / 1_000_000u128;

    // premium_bps = (notional / scale) * k_bps, capped
    let mut premium_bps_u: u128 =
        notional_e6.saturating_mul(funding_k_bps as u128) / funding_inv_scale_notional_e6.max(1);

    if premium_bps_u > (funding_max_premium_bps.unsigned_abs() as u128) {
        premium_bps_u = funding_max_premium_bps.unsigned_abs() as u128;
    }

    // Apply sign: if LP net long (net_lp_pos > 0), funding is positive
    let signed_premium_bps: i64 = if net_lp_pos > 0 {
        premium_bps_u as i64
    } else {
        -(premium_bps_u as i64)
    };

    // Convert to per-slot by dividing by horizon
    let mut per_slot: i64 = signed_premium_bps / (funding_horizon_slots as i64);

    // Sanity clamp: absolute max ±10000 bps/slot (100% per slot) to catch overflow bugs
    per_slot = per_slot.clamp(-10_000, 10_000);

    // Policy clamp: tighter bound per config
    if per_slot > funding_max_bps_per_slot {
        per_slot = funding_max_bps_per_slot;
    }
    if per_slot < -funding_max_bps_per_slot {
        per_slot = -funding_max_bps_per_slot;
    }
    per_slot
}

// =============================================================================
// Pure helpers for Kani verification (program-level invariants only)
// =============================================================================

/// Pure verification helpers for program-level authorization and CPI binding.
/// These are tested by Kani to prove wrapper-level security properties.
pub mod verify {
    use crate::constants::MATCHER_CONTEXT_LEN;

    /// Owner authorization: stored owner must match signer.
    /// Used by: DepositCollateral, WithdrawCollateral, TradeNoCpi, TradeCpi, CloseAccount
    #[inline]
    pub fn owner_ok(stored: [u8; 32], signer: [u8; 32]) -> bool {
        stored == signer
    }

    /// Admin authorization: admin must be non-zero (not burned) and match signer.
    /// Used by: SetRiskThreshold, UpdateAdmin
    #[inline]
    pub fn admin_ok(admin: [u8; 32], signer: [u8; 32]) -> bool {
        admin != [0u8; 32] && admin == signer
    }

    /// CPI identity binding: matcher program and context must match LP registration.
    /// This is the critical CPI security check.
    #[inline]
    pub fn matcher_identity_ok(
        lp_matcher_program: [u8; 32],
        lp_matcher_context: [u8; 32],
        provided_program: [u8; 32],
        provided_context: [u8; 32],
    ) -> bool {
        lp_matcher_program == provided_program && lp_matcher_context == provided_context
    }

    /// Matcher account shape validation.
    /// Checks: program is executable, context is not executable,
    /// context owner is program, context has sufficient length.
    #[derive(Clone, Copy)]
    pub struct MatcherAccountsShape {
        pub prog_executable: bool,
        pub ctx_executable: bool,
        pub ctx_owner_is_prog: bool,
        pub ctx_len_ok: bool,
    }

    #[inline]
    pub fn matcher_shape_ok(shape: MatcherAccountsShape) -> bool {
        shape.prog_executable
            && !shape.ctx_executable
            && shape.ctx_owner_is_prog
            && shape.ctx_len_ok
    }

    /// Check if context length meets minimum requirement.
    #[inline]
    pub fn ctx_len_sufficient(len: usize) -> bool {
        len >= MATCHER_CONTEXT_LEN
    }

    /// Gating is active when threshold > 0 AND balance <= threshold.
    #[inline]
    pub fn gate_active(threshold: u128, balance: u128) -> bool {
        threshold > 0 && balance <= threshold
    }

    /// Nonce update on success: advances by 1.
    #[inline]
    pub fn nonce_on_success(old: u64) -> u64 {
        old.wrapping_add(1)
    }

    /// Nonce update on failure: unchanged.
    #[inline]
    pub fn nonce_on_failure(old: u64) -> u64 {
        old
    }

    /// PDA key comparison: provided key must match expected derived key.
    #[inline]
    pub fn pda_key_matches(expected: [u8; 32], provided: [u8; 32]) -> bool {
        expected == provided
    }

    /// Trade size selection for CPI path: must use exec_size from matcher, not requested size.
    /// Returns the size that should be passed to engine.execute_trade.
    #[inline]
    pub fn cpi_trade_size(exec_size: i128, _requested_size: i128) -> i128 {
        exec_size // Must use exec_size, never requested_size
    }

    // =========================================================================
    // Account validation helpers
    // =========================================================================

    /// Signer requirement: account must be a signer.
    #[inline]
    pub fn signer_ok(is_signer: bool) -> bool {
        is_signer
    }

    /// Writable requirement: account must be writable.
    #[inline]
    pub fn writable_ok(is_writable: bool) -> bool {
        is_writable
    }

    /// Account count requirement: must have at least `need` accounts.
    #[inline]
    pub fn len_ok(actual: usize, need: usize) -> bool {
        actual >= need
    }

    /// LP PDA shape validation for TradeCpi.
    /// PDA must be system-owned, have zero data, and zero lamports.
    #[derive(Clone, Copy)]
    pub struct LpPdaShape {
        pub is_system_owned: bool,
        pub data_len_zero: bool,
        pub lamports_zero: bool,
    }

    #[inline]
    pub fn lp_pda_shape_ok(s: LpPdaShape) -> bool {
        s.is_system_owned && s.data_len_zero && s.lamports_zero
    }

    /// Oracle feed ID check: provided feed_id must match expected config feed_id.
    #[inline]
    pub fn oracle_feed_id_ok(expected: [u8; 32], provided: [u8; 32]) -> bool {
        expected == provided
    }

    /// Slab shape validation.
    /// Slab must be owned by this program and have correct length.
    #[derive(Clone, Copy)]
    pub struct SlabShape {
        pub owned_by_program: bool,
        pub correct_len: bool,
    }

    #[inline]
    pub fn slab_shape_ok(s: SlabShape) -> bool {
        s.owned_by_program && s.correct_len
    }

    // =========================================================================
    // Per-instruction authorization helpers
    // =========================================================================

    /// Single-owner instruction authorization (Deposit, Withdraw, Close).
    #[inline]
    pub fn single_owner_authorized(stored_owner: [u8; 32], signer: [u8; 32]) -> bool {
        owner_ok(stored_owner, signer)
    }

    /// Trade authorization: both user and LP owners must match signers.
    #[inline]
    pub fn trade_authorized(
        user_owner: [u8; 32],
        user_signer: [u8; 32],
        lp_owner: [u8; 32],
        lp_signer: [u8; 32],
    ) -> bool {
        owner_ok(user_owner, user_signer) && owner_ok(lp_owner, lp_signer)
    }

    // =========================================================================
    // TradeCpi decision logic - models the full wrapper policy
    // =========================================================================

    /// Decision outcome for TradeCpi instruction.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum TradeCpiDecision {
        /// Reject the trade - nonce unchanged, no engine call
        Reject,
        /// Accept the trade - nonce incremented, engine called with chosen_size
        Accept { new_nonce: u64, chosen_size: i128 },
    }

    /// Pure decision function for TradeCpi instruction.
    /// Models the wrapper's full policy without touching the risk engine.
    ///
    /// # Arguments
    /// * `old_nonce` - Current nonce before this trade
    /// * `shape` - Matcher account shape validation inputs
    /// * `identity_ok` - Whether matcher identity matches LP registration
    /// * `pda_ok` - Whether LP PDA matches expected derivation
    /// * `abi_ok` - Whether matcher return passes ABI validation
    /// * `user_auth_ok` - Whether user signer matches user owner
    /// * `lp_auth_ok` - Whether LP signer matches LP owner
    /// * `gate_active` - Whether the risk-reduction gate is active
    /// * `risk_increase` - Whether this trade would increase system risk
    /// * `exec_size` - The exec_size from matcher return
    #[inline]
    pub fn decide_trade_cpi(
        old_nonce: u64,
        shape: MatcherAccountsShape,
        identity_ok: bool,
        pda_ok: bool,
        abi_ok: bool,
        user_auth_ok: bool,
        lp_auth_ok: bool,
        gate_active: bool,
        risk_increase: bool,
        exec_size: i128,
    ) -> TradeCpiDecision {
        // Check in order of actual program execution:
        // 1. Matcher shape validation
        if !matcher_shape_ok(shape) {
            return TradeCpiDecision::Reject;
        }
        // 2. PDA validation
        if !pda_ok {
            return TradeCpiDecision::Reject;
        }
        // 3. Owner authorization (user and LP)
        if !user_auth_ok || !lp_auth_ok {
            return TradeCpiDecision::Reject;
        }
        // 4. Matcher identity binding
        if !identity_ok {
            return TradeCpiDecision::Reject;
        }
        // 5. ABI validation (after CPI returns)
        if !abi_ok {
            return TradeCpiDecision::Reject;
        }
        // 6. Risk gate check
        if gate_active && risk_increase {
            return TradeCpiDecision::Reject;
        }
        // All checks passed - accept the trade
        TradeCpiDecision::Accept {
            new_nonce: nonce_on_success(old_nonce),
            chosen_size: cpi_trade_size(exec_size, 0), // 0 is placeholder for requested_size
        }
    }

    /// Extract nonce from TradeCpiDecision.
    #[inline]
    pub fn decision_nonce(old_nonce: u64, decision: TradeCpiDecision) -> u64 {
        match decision {
            TradeCpiDecision::Reject => nonce_on_failure(old_nonce),
            TradeCpiDecision::Accept { new_nonce, .. } => new_nonce,
        }
    }

    // =========================================================================
    // ABI validation from real MatcherReturn inputs
    // =========================================================================

    /// Pure matcher return fields for Kani verification.
    /// Mirrors matcher_abi::MatcherReturn but lives in verify module for Kani access.
    #[derive(Debug, Clone, Copy)]
    pub struct MatcherReturnFields {
        pub abi_version: u32,
        pub flags: u32,
        pub exec_price_e6: u64,
        pub exec_size: i128,
        pub req_id: u64,
        pub lp_account_id: u64,
        pub oracle_price_e6: u64,
        pub reserved: u64,
    }

    impl MatcherReturnFields {
        /// Convert to matcher_abi::MatcherReturn for validation.
        #[inline]
        pub fn to_matcher_return(&self) -> crate::matcher_abi::MatcherReturn {
            crate::matcher_abi::MatcherReturn {
                abi_version: self.abi_version,
                flags: self.flags,
                exec_price_e6: self.exec_price_e6,
                exec_size: self.exec_size,
                req_id: self.req_id,
                lp_account_id: self.lp_account_id,
                oracle_price_e6: self.oracle_price_e6,
                reserved: self.reserved,
            }
        }
    }

    /// ABI validation of matcher return - calls the real validate_matcher_return.
    /// Returns true iff the matcher return passes all ABI checks.
    /// This avoids logic duplication and ensures Kani proofs test the real code.
    #[inline]
    pub fn abi_ok(
        ret: MatcherReturnFields,
        expected_lp_account_id: u64,
        expected_oracle_price_e6: u64,
        req_size: i128,
        expected_req_id: u64,
    ) -> bool {
        let matcher_ret = ret.to_matcher_return();
        crate::matcher_abi::validate_matcher_return(
            &matcher_ret,
            expected_lp_account_id,
            expected_oracle_price_e6,
            req_size,
            expected_req_id,
        )
        .is_ok()
    }

    /// Decision function for TradeCpi that computes ABI validity from real inputs.
    /// This is the mechanically-tied version that proves program-level policies.
    ///
    /// # Arguments
    /// * `old_nonce` - Current nonce before this trade
    /// * `shape` - Matcher account shape validation inputs
    /// * `identity_ok` - Whether matcher identity matches LP registration
    /// * `pda_ok` - Whether LP PDA matches expected derivation
    /// * `user_auth_ok` - Whether user signer matches user owner
    /// * `lp_auth_ok` - Whether LP signer matches LP owner
    /// * `gate_active` - Whether the risk-reduction gate is active
    /// * `risk_increase` - Whether this trade would increase system risk
    /// * `ret` - The matcher return fields (from CPI)
    /// * `lp_account_id` - Expected LP account ID from request
    /// * `oracle_price_e6` - Expected oracle price from request
    /// * `req_size` - Requested trade size
    #[inline]
    pub fn decide_trade_cpi_from_ret(
        old_nonce: u64,
        shape: MatcherAccountsShape,
        identity_ok: bool,
        pda_ok: bool,
        user_auth_ok: bool,
        lp_auth_ok: bool,
        gate_is_active: bool,
        risk_increase: bool,
        ret: MatcherReturnFields,
        lp_account_id: u64,
        oracle_price_e6: u64,
        req_size: i128,
    ) -> TradeCpiDecision {
        // Check in order of actual program execution:
        // 1. Matcher shape validation
        if !matcher_shape_ok(shape) {
            return TradeCpiDecision::Reject;
        }
        // 2. PDA validation
        if !pda_ok {
            return TradeCpiDecision::Reject;
        }
        // 3. Owner authorization (user and LP)
        if !user_auth_ok || !lp_auth_ok {
            return TradeCpiDecision::Reject;
        }
        // 4. Matcher identity binding
        if !identity_ok {
            return TradeCpiDecision::Reject;
        }
        // 5. Compute req_id from nonce and validate ABI
        let req_id = nonce_on_success(old_nonce);
        if !abi_ok(ret, lp_account_id, oracle_price_e6, req_size, req_id) {
            return TradeCpiDecision::Reject;
        }
        // 6. Risk gate check
        if gate_is_active && risk_increase {
            return TradeCpiDecision::Reject;
        }
        // All checks passed - accept the trade
        TradeCpiDecision::Accept {
            new_nonce: req_id,
            chosen_size: cpi_trade_size(ret.exec_size, req_size),
        }
    }

    // =========================================================================
    // TradeNoCpi decision logic
    // =========================================================================

    /// Decision outcome for TradeNoCpi instruction.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum TradeNoCpiDecision {
        Reject,
        Accept,
    }

    /// Pure decision function for TradeNoCpi instruction.
    #[inline]
    pub fn decide_trade_nocpi(
        user_auth_ok: bool,
        lp_auth_ok: bool,
        gate_active: bool,
        risk_increase: bool,
    ) -> TradeNoCpiDecision {
        if !user_auth_ok || !lp_auth_ok {
            return TradeNoCpiDecision::Reject;
        }
        if gate_active && risk_increase {
            return TradeNoCpiDecision::Reject;
        }
        TradeNoCpiDecision::Accept
    }

    // =========================================================================
    // Other instruction decision logic
    // =========================================================================

    /// Simple Accept/Reject decision for single-check instructions.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum SimpleDecision {
        Reject,
        Accept,
    }

    /// Decision for Deposit/Withdraw/Close: requires owner authorization.
    #[inline]
    pub fn decide_single_owner_op(owner_auth_ok: bool) -> SimpleDecision {
        if owner_auth_ok {
            SimpleDecision::Accept
        } else {
            SimpleDecision::Reject
        }
    }

    /// Decision for KeeperCrank:
    /// - Permissionless mode (caller_idx == u16::MAX): always accept
    /// - Self-crank mode: idx must exist AND owner must match signer
    #[inline]
    pub fn decide_crank(
        permissionless: bool,
        idx_exists: bool,
        stored_owner: [u8; 32],
        signer: [u8; 32],
    ) -> SimpleDecision {
        if permissionless {
            SimpleDecision::Accept
        } else if idx_exists && owner_ok(stored_owner, signer) {
            SimpleDecision::Accept
        } else {
            SimpleDecision::Reject
        }
    }

    /// Decision for admin operations (SetRiskThreshold, UpdateAdmin).
    #[inline]
    pub fn decide_admin_op(admin: [u8; 32], signer: [u8; 32]) -> SimpleDecision {
        if admin_ok(admin, signer) {
            SimpleDecision::Accept
        } else {
            SimpleDecision::Reject
        }
    }

    // =========================================================================
    // KeeperCrank with allow_panic decision logic
    // =========================================================================

    /// Decision for KeeperCrank with allow_panic support.
    /// - If allow_panic != 0: requires admin authorization
    /// - If allow_panic == 0 and permissionless: always accept
    /// - If allow_panic == 0 and self-crank: requires idx exists and owner match
    #[inline]
    pub fn decide_keeper_crank_with_panic(
        allow_panic: u8,
        admin: [u8; 32],
        signer: [u8; 32],
        permissionless: bool,
        idx_exists: bool,
        stored_owner: [u8; 32],
    ) -> SimpleDecision {
        // If allow_panic is requested, must have admin authorization
        if allow_panic != 0 {
            if !admin_ok(admin, signer) {
                return SimpleDecision::Reject;
            }
        }
        // Normal crank logic
        decide_crank(permissionless, idx_exists, stored_owner, signer)
    }

    // =========================================================================
    // Oracle inversion math (pure logic)
    // =========================================================================

    /// Inversion constant: 1e12 for price_e6 * inverted_e6 = 1e12
    pub const INVERSION_CONSTANT: u128 = 1_000_000_000_000;

    /// Invert oracle price: inverted_e6 = 1e12 / raw_e6
    /// Returns None if raw == 0 or result overflows u64.
    #[inline]
    pub fn invert_price_e6(raw: u64, invert: u8) -> Option<u64> {
        if invert == 0 {
            return Some(raw);
        }
        if raw == 0 {
            return None;
        }
        let inverted = INVERSION_CONSTANT / (raw as u128);
        if inverted == 0 {
            return None;
        }
        if inverted > u64::MAX as u128 {
            return None;
        }
        Some(inverted as u64)
    }

    /// Scale oracle price by unit_scale: scaled_e6 = price_e6 / unit_scale
    /// Returns None if result would be zero (price too small for scale).
    ///
    /// CRITICAL: This ensures oracle-derived values (entry_price, mark_pnl, position_value)
    /// are in the same scale as capital (which is stored in units via base_to_units).
    /// Without this scaling, margin checks would compare units to base tokens incorrectly.
    #[inline]
    pub fn scale_price_e6(price: u64, unit_scale: u32) -> Option<u64> {
        if unit_scale <= 1 {
            return Some(price);
        }
        let scaled = price / unit_scale as u64;
        if scaled == 0 {
            return None;
        }
        Some(scaled)
    }

    // =========================================================================
    // Unit scale conversion math (pure logic)
    // =========================================================================

    /// Convert base amount to (units, dust).
    /// If scale == 0: returns (base, 0).
    /// Otherwise: units = base / scale, dust = base % scale.
    #[inline]
    pub fn base_to_units(base: u64, scale: u32) -> (u64, u64) {
        if scale == 0 {
            return (base, 0);
        }
        let s = scale as u64;
        (base / s, base % s)
    }

    /// Convert units to base amount (saturating).
    /// If scale == 0: returns units.
    /// Otherwise: returns units * scale (saturating).
    #[inline]
    pub fn units_to_base(units: u64, scale: u32) -> u64 {
        if scale == 0 {
            return units;
        }
        units.saturating_mul(scale as u64)
    }

    // =========================================================================
    // Withdraw alignment check (pure logic)
    // =========================================================================

    /// Check if withdraw amount is properly aligned to unit_scale.
    /// If scale == 0: always aligned.
    /// Otherwise: amount must be divisible by scale.
    #[inline]
    pub fn withdraw_amount_aligned(amount: u64, scale: u32) -> bool {
        if scale == 0 {
            return true;
        }
        amount % (scale as u64) == 0
    }

    // =========================================================================
    // Dust bookkeeping math (pure logic)
    // =========================================================================

    /// Accumulate dust: old_dust + added_dust (saturating).
    #[inline]
    pub fn accumulate_dust(old_dust: u64, added_dust: u64) -> u64 {
        old_dust.saturating_add(added_dust)
    }

    /// Sweep dust into units: returns (units_swept, remaining_dust).
    /// If scale == 0: returns (dust, 0) - all dust becomes units.
    /// Otherwise: units_swept = dust / scale, remaining = dust % scale.
    #[inline]
    pub fn sweep_dust(dust: u64, scale: u32) -> (u64, u64) {
        if scale == 0 {
            return (dust, 0);
        }
        let s = scale as u64;
        (dust / s, dust % s)
    }

    // =========================================================================
    // InitMarket scale validation (pure logic)
    // =========================================================================

    /// Validate unit_scale for InitMarket instruction.
    /// Returns true if scale is within allowed bounds.
    /// scale=0: disables scaling, 1:1 base tokens to units, dust always 0.
    /// scale=1..=MAX_UNIT_SCALE: enables scaling with dust tracking.
    #[inline]
    pub fn init_market_scale_ok(unit_scale: u32) -> bool {
        unit_scale <= crate::constants::MAX_UNIT_SCALE
    }
}

// 2. mod zc (Zero-Copy unsafe island)
#[allow(unsafe_code)]
pub mod zc {
    use crate::constants::{ENGINE_ALIGN, ENGINE_LEN, ENGINE_OFF};
    // use core::mem::offset_of;
    use crate::percolator::RiskEngine;
    use crate::solana_program::program_error::ProgramError;

    // Use const to export the actual offset for debugging
    pub const ACCOUNTS_OFFSET: usize = 16; // magic(8) + version(4) + padding(4)

    /// Old slab length (before Account struct reordering migration)
    /// Old slabs support up to 4095 accounts, new slabs support 4096.
    const OLD_ENGINE_LEN: usize = ENGINE_LEN - 8;

    #[inline]
    pub fn engine_ref<'a>(data: &'a [u8]) -> Result<&'a RiskEngine, ProgramError> {
        // Accept old slabs (ENGINE_LEN - 8) for backward compatibility
        if data.len() < ENGINE_OFF + OLD_ENGINE_LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        let ptr = unsafe { data.as_ptr().add(ENGINE_OFF) };
        if (ptr as usize) % ENGINE_ALIGN != 0 {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(unsafe { &*(ptr as *const RiskEngine) })
    }

    #[inline]
    pub fn engine_mut<'a>(data: &'a mut [u8]) -> Result<&'a mut RiskEngine, ProgramError> {
        // Accept old slabs (ENGINE_LEN - 8) for backward compatibility
        if data.len() < ENGINE_OFF + OLD_ENGINE_LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        let ptr = unsafe { data.as_mut_ptr().add(ENGINE_OFF) };
        if (ptr as usize) % ENGINE_ALIGN != 0 {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(unsafe { &mut *(ptr as *mut RiskEngine) })
    }

    // NOTE: engine_write was removed because it requires passing RiskEngine by value,
    // which stack-allocates the ~6MB struct and causes stack overflow in BPF.
    // Use engine_mut() + init_in_place() instead for initialization.

    use crate::solana_program::{
        account_info::AccountInfo, instruction::Instruction as SolInstruction,
        program::invoke_signed,
    };

    /// Invoke the matcher program via CPI with proper lifetime coercion.
    ///
    /// This is the ONLY place where unsafe lifetime transmute is allowed.
    /// The transmute is sound because:
    /// - We are shortening lifetime from 'a (caller) to local scope
    /// - The AccountInfo is only used for the duration of invoke_signed
    /// - We don't hold references past the function call
    #[inline]
    #[allow(unsafe_code)]
    pub fn invoke_signed_trade<'a>(
        ix: &SolInstruction,
        a_lp_pda: &AccountInfo<'a>,
        a_matcher_ctx: &AccountInfo<'a>,
        seeds: &[&[u8]],
    ) -> Result<(), ProgramError> {
        // SAFETY: AccountInfos have lifetime 'a from the caller.
        // We clone them to get owned values (still with 'a lifetime internally).
        // The invoke_signed call consumes them by reference and returns.
        // No lifetime extension occurs.
        let infos = [a_lp_pda.clone(), a_matcher_ctx.clone()];
        invoke_signed(ix, &infos, &[seeds])
    }
}

pub mod matcher_abi {
    use crate::constants::MATCHER_ABI_VERSION;
    use crate::solana_program::program_error::ProgramError;

    /// Matcher return flags
    pub const FLAG_VALID: u32 = 1; // bit0: response is valid
    pub const FLAG_PARTIAL_OK: u32 = 2; // bit1: partial fill including zero allowed
    pub const FLAG_REJECTED: u32 = 4; // bit2: trade rejected by matcher

    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct MatcherReturn {
        pub abi_version: u32,
        pub flags: u32,
        pub exec_price_e6: u64,
        pub exec_size: i128,
        pub req_id: u64,
        pub lp_account_id: u64,
        pub oracle_price_e6: u64,
        pub reserved: u64,
    }

    pub fn read_matcher_return(ctx: &[u8]) -> Result<MatcherReturn, ProgramError> {
        if ctx.len() < 64 {
            return Err(ProgramError::InvalidAccountData);
        }
        let abi_version = u32::from_le_bytes(ctx[0..4].try_into().unwrap());
        let flags = u32::from_le_bytes(ctx[4..8].try_into().unwrap());
        let exec_price_e6 = u64::from_le_bytes(ctx[8..16].try_into().unwrap());
        let exec_size = i128::from_le_bytes(ctx[16..32].try_into().unwrap());
        let req_id = u64::from_le_bytes(ctx[32..40].try_into().unwrap());
        let lp_account_id = u64::from_le_bytes(ctx[40..48].try_into().unwrap());
        let oracle_price_e6 = u64::from_le_bytes(ctx[48..56].try_into().unwrap());
        let reserved = u64::from_le_bytes(ctx[56..64].try_into().unwrap());

        Ok(MatcherReturn {
            abi_version,
            flags,
            exec_price_e6,
            exec_size,
            req_id,
            lp_account_id,
            oracle_price_e6,
            reserved,
        })
    }

    pub fn validate_matcher_return(
        ret: &MatcherReturn,
        lp_account_id: u64,
        oracle_price_e6: u64,
        req_size: i128,
        req_id: u64,
    ) -> Result<(), ProgramError> {
        // Check ABI version
        if ret.abi_version != MATCHER_ABI_VERSION {
            return Err(ProgramError::InvalidAccountData);
        }
        // Must have VALID flag set
        if (ret.flags & FLAG_VALID) == 0 {
            return Err(ProgramError::InvalidAccountData);
        }
        // Must not have REJECTED flag set
        if (ret.flags & FLAG_REJECTED) != 0 {
            return Err(ProgramError::InvalidAccountData);
        }

        // Validate echoed fields match request
        if ret.lp_account_id != lp_account_id {
            return Err(ProgramError::InvalidAccountData);
        }
        if ret.oracle_price_e6 != oracle_price_e6 {
            return Err(ProgramError::InvalidAccountData);
        }
        if ret.reserved != 0 {
            return Err(ProgramError::InvalidAccountData);
        }
        if ret.req_id != req_id {
            return Err(ProgramError::InvalidAccountData);
        }

        // Require exec_price_e6 != 0 always - avoids "all zeros but valid flag" ambiguity
        if ret.exec_price_e6 == 0 {
            return Err(ProgramError::InvalidAccountData);
        }

        // Zero exec_size requires PARTIAL_OK flag
        if ret.exec_size == 0 {
            if (ret.flags & FLAG_PARTIAL_OK) == 0 {
                return Err(ProgramError::InvalidAccountData);
            }
            // Zero fill with PARTIAL_OK is allowed - return early
            return Ok(());
        }

        // Size constraints (use unsigned_abs to avoid i128::MIN overflow)
        if ret.exec_size.unsigned_abs() > req_size.unsigned_abs() {
            return Err(ProgramError::InvalidAccountData);
        }
        if req_size != 0 {
            if ret.exec_size.signum() != req_size.signum() {
                return Err(ProgramError::InvalidAccountData);
            }
        }
        Ok(())
    }
}

// 3. mod error
pub mod error {
    use crate::percolator::RiskError;
    use crate::solana_program::program_error::ProgramError;

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub enum PercolatorError {
        InvalidMagic,
        InvalidVersion,
        AlreadyInitialized,
        NotInitialized,
        InvalidSlabLen,
        InvalidOracleKey,
        OracleStale,
        OracleConfTooWide,
        InvalidVaultAta,
        InvalidMint,
        ExpectedSigner,
        ExpectedWritable,
        OracleInvalid,
        EngineInsufficientBalance,
        EngineUndercollateralized,
        EngineUnauthorized,
        EngineInvalidMatchingEngine,
        EnginePnlNotWarmedUp,
        EngineOverflow,
        EngineAccountNotFound,
        EngineNotAnLPAccount,
        EnginePositionSizeMismatch,
        EngineRiskReductionOnlyMode,
        EngineAccountKindMismatch,
        InvalidTokenAccount,
        InvalidTokenProgram,
        InvalidConfigParam,
        HyperpTradeNoCpiDisabled,
        GhostSignatureNotFound,
        GhostSignatureInvalid,
        GhostSignatureMismatch,
    }

    impl From<PercolatorError> for ProgramError {
        fn from(e: PercolatorError) -> Self {
            ProgramError::Custom(e as u32)
        }
    }

    pub fn map_risk_error(e: RiskError) -> ProgramError {
        let err = match e {
            RiskError::InsufficientBalance => PercolatorError::EngineInsufficientBalance,
            RiskError::Undercollateralized => PercolatorError::EngineUndercollateralized,
            RiskError::Unauthorized => PercolatorError::EngineUnauthorized,
            RiskError::InvalidMatchingEngine => PercolatorError::EngineInvalidMatchingEngine,
            RiskError::PnlNotWarmedUp => PercolatorError::EnginePnlNotWarmedUp,
            RiskError::Overflow => PercolatorError::EngineOverflow,
            RiskError::AccountNotFound => PercolatorError::EngineAccountNotFound,
            RiskError::NotAnLPAccount => PercolatorError::EngineNotAnLPAccount,
            RiskError::PositionSizeMismatch => PercolatorError::EnginePositionSizeMismatch,
            RiskError::AccountKindMismatch => PercolatorError::EngineAccountKindMismatch,
        };
        ProgramError::Custom(err as u32)
    }
}

// 4. mod ix
pub mod ix {
    use crate::percolator::{RiskParams, U128};
    use crate::solana_program::{program_error::ProgramError, pubkey::Pubkey};

    #[derive(Debug)]
    pub enum Instruction {
        InitMarket {
            admin: Pubkey,
            collateral_mint: Pubkey,
            /// Pyth feed ID for the index price (32 bytes).
            /// If all zeros, enables Hyperp mode (internal mark/index, no external oracle).
            index_feed_id: [u8; 32],
            /// Maximum staleness in seconds
            max_staleness_secs: u64,
            conf_filter_bps: u16,
            /// If non-zero, invert oracle price (raw -> 1e12/raw)
            invert: u8,
            /// Lamports per Unit for boundary conversion (0 = no scaling)
            unit_scale: u32,
            /// Initial mark price in e6 format. Required (non-zero) if Hyperp mode.
            initial_mark_price_e6: u64,
            risk_params: RiskParams,
        },
        InitUser {
            fee_payment: u64,
        },
        InitLP {
            matcher_program: Pubkey,
            matcher_context: Pubkey,
            fee_payment: u64,
        },
        DepositCollateral {
            user_idx: u16,
            amount: u64,
        },
        WithdrawCollateral {
            user_idx: u16,
            amount: u64,
        },
        KeeperCrank {
            caller_idx: u16,
            allow_panic: u8,
        },
        TradeNoCpi {
            lp_idx: u16,
            user_idx: u16,
            size: i128,
        },
        LiquidateAtOracle {
            target_idx: u16,
        },
        CloseAccount {
            user_idx: u16,
        },
        TopUpInsurance {
            amount: u64,
        },
        TradeCpi {
            lp_idx: u16,
            user_idx: u16,
            size: i128,
        },
        SetRiskThreshold {
            new_threshold: u128,
        },
        UpdateAdmin {
            new_admin: Pubkey,
        },
        /// Close the market slab and recover SOL to admin.
        /// Requires: no active accounts, no vault funds, no insurance funds.
        CloseSlab,
        /// Update configurable parameters (funding + threshold). Admin only.
        UpdateConfig {
            funding_horizon_slots: u64,
            funding_k_bps: u64,
            funding_inv_scale_notional_e6: u128,
            funding_max_premium_bps: i64,
            funding_max_bps_per_slot: i64,
            thresh_floor: u128,
            thresh_risk_bps: u64,
            thresh_update_interval_slots: u64,
            thresh_step_bps: u64,
            thresh_alpha_bps: u64,
            thresh_min: u128,
            thresh_max: u128,
            thresh_min_step: u128,
        },
        /// Set maintenance fee per slot (admin only)
        SetMaintenanceFee {
            new_fee: u128,
        },
        /// Set the oracle price authority (admin only).
        /// Authority can push prices instead of requiring Pyth/Chainlink.
        /// Pass zero pubkey to disable and require Pyth/Chainlink.
        SetOracleAuthority {
            new_authority: Pubkey,
        },
        /// Push oracle price (oracle authority only).
        /// Stores the price for use by crank/trade operations.
        PushOraclePrice {
            price_e6: u64,
            timestamp: i64,
        },
        /// Set oracle price circuit breaker cap (admin only).
        /// max_change_e2bps in 0.01 bps units (1_000_000 = 100%). 0 = disabled.
        SetOraclePriceCap {
            max_change_e2bps: u64,
        },
        /// Resolve market: force-close all positions at admin oracle price, enter withdraw-only mode.
        /// Admin only. Uses authority_price_e6 as settlement price.
        ResolveMarket,
        /// Withdraw insurance fund balance (admin only, requires RESOLVED flag).
        WithdrawInsurance,
        /// Admin force-close an abandoned account after market resolution.
        /// Requires RESOLVED flag, zero position, admin signer.
        AdminForceCloseAccount {
            user_idx: u16,
        },
        RegisterGhost {
            user_idx: u16,
            ghost_key: Pubkey,
        },
        TradeGhost {
            lp_idx: u16,
            user_idx: u16,
            size: i128,
        },
    }

    impl Instruction {
        pub fn decode(input: &[u8]) -> Result<Self, ProgramError> {
            let (&tag, mut rest) = input
                .split_first()
                .ok_or(ProgramError::InvalidInstructionData)?;

            match tag {
                0 => {
                    // InitMarket
                    let admin = read_pubkey(&mut rest)?;
                    let collateral_mint = read_pubkey(&mut rest)?;
                    let index_feed_id = read_bytes32(&mut rest)?;
                    let max_staleness_secs = read_u64(&mut rest)?;
                    let conf_filter_bps = read_u16(&mut rest)?;
                    let invert = read_u8(&mut rest)?;
                    let unit_scale = read_u32(&mut rest)?;
                    let initial_mark_price_e6 = read_u64(&mut rest)?;
                    let risk_params = read_risk_params(&mut rest)?;
                    Ok(Instruction::InitMarket {
                        admin,
                        collateral_mint,
                        index_feed_id,
                        max_staleness_secs,
                        conf_filter_bps,
                        invert,
                        unit_scale,
                        initial_mark_price_e6,
                        risk_params,
                    })
                }
                1 => {
                    // InitUser
                    let fee_payment = read_u64(&mut rest)?;
                    Ok(Instruction::InitUser { fee_payment })
                }
                2 => {
                    // InitLP
                    let matcher_program = read_pubkey(&mut rest)?;
                    let matcher_context = read_pubkey(&mut rest)?;
                    let fee_payment = read_u64(&mut rest)?;
                    Ok(Instruction::InitLP {
                        matcher_program,
                        matcher_context,
                        fee_payment,
                    })
                }
                3 => {
                    // Deposit
                    let user_idx = read_u16(&mut rest)?;
                    let amount = read_u64(&mut rest)?;
                    Ok(Instruction::DepositCollateral { user_idx, amount })
                }
                4 => {
                    // Withdraw
                    let user_idx = read_u16(&mut rest)?;
                    let amount = read_u64(&mut rest)?;
                    Ok(Instruction::WithdrawCollateral { user_idx, amount })
                }
                5 => {
                    // KeeperCrank
                    let caller_idx = read_u16(&mut rest)?;
                    let allow_panic = read_u8(&mut rest)?;
                    Ok(Instruction::KeeperCrank {
                        caller_idx,
                        allow_panic,
                    })
                }
                6 => {
                    // TradeNoCpi
                    let lp_idx = read_u16(&mut rest)?;
                    let user_idx = read_u16(&mut rest)?;
                    let size = read_i128(&mut rest)?;
                    Ok(Instruction::TradeNoCpi {
                        lp_idx,
                        user_idx,
                        size,
                    })
                }
                7 => {
                    // LiquidateAtOracle
                    let target_idx = read_u16(&mut rest)?;
                    Ok(Instruction::LiquidateAtOracle { target_idx })
                }
                8 => {
                    // CloseAccount
                    let user_idx = read_u16(&mut rest)?;
                    Ok(Instruction::CloseAccount { user_idx })
                }
                9 => {
                    // TopUpInsurance
                    let amount = read_u64(&mut rest)?;
                    Ok(Instruction::TopUpInsurance { amount })
                }
                10 => {
                    // TradeCpi
                    let lp_idx = read_u16(&mut rest)?;
                    let user_idx = read_u16(&mut rest)?;
                    let size = read_i128(&mut rest)?;
                    Ok(Instruction::TradeCpi {
                        lp_idx,
                        user_idx,
                        size,
                    })
                }
                11 => {
                    // SetRiskThreshold
                    let new_threshold = read_u128(&mut rest)?;
                    Ok(Instruction::SetRiskThreshold { new_threshold })
                }
                12 => {
                    // UpdateAdmin
                    let new_admin = read_pubkey(&mut rest)?;
                    Ok(Instruction::UpdateAdmin { new_admin })
                }
                13 => {
                    // CloseSlab
                    Ok(Instruction::CloseSlab)
                }
                14 => {
                    // UpdateConfig
                    let funding_horizon_slots = read_u64(&mut rest)?;
                    let funding_k_bps = read_u64(&mut rest)?;
                    let funding_inv_scale_notional_e6 = read_u128(&mut rest)?;
                    let funding_max_premium_bps = read_i64(&mut rest)?;
                    let funding_max_bps_per_slot = read_i64(&mut rest)?;
                    let thresh_floor = read_u128(&mut rest)?;
                    let thresh_risk_bps = read_u64(&mut rest)?;
                    let thresh_update_interval_slots = read_u64(&mut rest)?;
                    let thresh_step_bps = read_u64(&mut rest)?;
                    let thresh_alpha_bps = read_u64(&mut rest)?;
                    let thresh_min = read_u128(&mut rest)?;
                    let thresh_max = read_u128(&mut rest)?;
                    let thresh_min_step = read_u128(&mut rest)?;
                    Ok(Instruction::UpdateConfig {
                        funding_horizon_slots,
                        funding_k_bps,
                        funding_inv_scale_notional_e6,
                        funding_max_premium_bps,
                        funding_max_bps_per_slot,
                        thresh_floor,
                        thresh_risk_bps,
                        thresh_update_interval_slots,
                        thresh_step_bps,
                        thresh_alpha_bps,
                        thresh_min,
                        thresh_max,
                        thresh_min_step,
                    })
                }
                15 => {
                    // SetMaintenanceFee
                    let new_fee = read_u128(&mut rest)?;
                    Ok(Instruction::SetMaintenanceFee { new_fee })
                }
                16 => {
                    // SetOracleAuthority
                    let new_authority = read_pubkey(&mut rest)?;
                    Ok(Instruction::SetOracleAuthority { new_authority })
                }
                17 => {
                    // PushOraclePrice
                    let price_e6 = read_u64(&mut rest)?;
                    let timestamp = read_i64(&mut rest)?;
                    Ok(Instruction::PushOraclePrice {
                        price_e6,
                        timestamp,
                    })
                }
                18 => {
                    // SetOraclePriceCap
                    let max_change_e2bps = read_u64(&mut rest)?;
                    Ok(Instruction::SetOraclePriceCap { max_change_e2bps })
                }
                19 => Ok(Instruction::ResolveMarket),
                20 => Ok(Instruction::WithdrawInsurance),
                21 => {
                    let user_idx = read_u16(&mut rest)?;
                    Ok(Instruction::AdminForceCloseAccount { user_idx })
                }
                22 => {
                    let user_idx = read_u16(&mut rest)?;
                    let ghost_key = read_pubkey(&mut rest)?;
                    Ok(Instruction::RegisterGhost { user_idx, ghost_key })
                }
                23 => {
                    let lp_idx = read_u16(&mut rest)?;
                    let user_idx = read_u16(&mut rest)?;
                    let size = read_i128(&mut rest)?;
                    Ok(Instruction::TradeGhost {
                        lp_idx,
                        user_idx,
                        size,
                    })
                }
                _ => Err(ProgramError::InvalidInstructionData),
            }
        }
    }

    fn read_u8(input: &mut &[u8]) -> Result<u8, ProgramError> {
        let (&val, rest) = input
            .split_first()
            .ok_or(ProgramError::InvalidInstructionData)?;
        *input = rest;
        Ok(val)
    }

    fn read_u16(input: &mut &[u8]) -> Result<u16, ProgramError> {
        if input.len() < 2 {
            return Err(ProgramError::InvalidInstructionData);
        }
        let (bytes, rest) = input.split_at(2);
        *input = rest;
        Ok(u16::from_le_bytes(bytes.try_into().unwrap()))
    }

    fn read_u32(input: &mut &[u8]) -> Result<u32, ProgramError> {
        if input.len() < 4 {
            return Err(ProgramError::InvalidInstructionData);
        }
        let (bytes, rest) = input.split_at(4);
        *input = rest;
        Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
    }

    fn read_u64(input: &mut &[u8]) -> Result<u64, ProgramError> {
        if input.len() < 8 {
            return Err(ProgramError::InvalidInstructionData);
        }
        let (bytes, rest) = input.split_at(8);
        *input = rest;
        Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
    }

    fn read_i64(input: &mut &[u8]) -> Result<i64, ProgramError> {
        if input.len() < 8 {
            return Err(ProgramError::InvalidInstructionData);
        }
        let (bytes, rest) = input.split_at(8);
        *input = rest;
        Ok(i64::from_le_bytes(bytes.try_into().unwrap()))
    }

    fn read_i128(input: &mut &[u8]) -> Result<i128, ProgramError> {
        if input.len() < 16 {
            return Err(ProgramError::InvalidInstructionData);
        }
        let (bytes, rest) = input.split_at(16);
        *input = rest;
        Ok(i128::from_le_bytes(bytes.try_into().unwrap()))
    }

    fn read_u128(input: &mut &[u8]) -> Result<u128, ProgramError> {
        if input.len() < 16 {
            return Err(ProgramError::InvalidInstructionData);
        }
        let (bytes, rest) = input.split_at(16);
        *input = rest;
        Ok(u128::from_le_bytes(bytes.try_into().unwrap()))
    }

    fn read_pubkey(input: &mut &[u8]) -> Result<Pubkey, ProgramError> {
        if input.len() < 32 {
            return Err(ProgramError::InvalidInstructionData);
        }
        let (bytes, rest) = input.split_at(32);
        *input = rest;
        Ok(Pubkey::new_from_array(bytes.try_into().unwrap()))
    }

    fn read_bytes32(input: &mut &[u8]) -> Result<[u8; 32], ProgramError> {
        if input.len() < 32 {
            return Err(ProgramError::InvalidInstructionData);
        }
        let (bytes, rest) = input.split_at(32);
        *input = rest;
        Ok(bytes.try_into().unwrap())
    }

    fn read_risk_params(input: &mut &[u8]) -> Result<RiskParams, ProgramError> {
        Ok(RiskParams {
            warmup_period_slots: read_u64(input)?,
            maintenance_margin_bps: read_u64(input)?,
            initial_margin_bps: read_u64(input)?,
            trading_fee_bps: read_u64(input)?,
            max_accounts: read_u64(input)?,
            new_account_fee: U128::new(read_u128(input)?),
            risk_reduction_threshold: U128::new(read_u128(input)?),
            maintenance_fee_per_slot: U128::new(read_u128(input)?),
            max_crank_staleness_slots: read_u64(input)?,
            liquidation_fee_bps: read_u64(input)?,
            liquidation_fee_cap: U128::new(read_u128(input)?),
            liquidation_buffer_bps: read_u64(input)?,
            min_liquidation_abs: U128::new(read_u128(input)?),
        })
    }
}

// 5. mod accounts (Pinocchio validation)
pub mod accounts {
    use crate::error::PercolatorError;
    use crate::solana_program::{account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey};

    pub fn expect_len(accounts: &[AccountInfo], n: usize) -> Result<(), ProgramError> {
        // Length check via verify helper (Kani-provable)
        if !crate::verify::len_ok(accounts.len(), n) {
            return Err(ProgramError::NotEnoughAccountKeys);
        }
        Ok(())
    }

    pub fn expect_signer(ai: &AccountInfo) -> Result<(), ProgramError> {
        // Signer check via verify helper (Kani-provable)
        if !crate::verify::signer_ok(ai.is_signer) {
            return Err(PercolatorError::ExpectedSigner.into());
        }
        Ok(())
    }

    pub fn expect_writable(ai: &AccountInfo) -> Result<(), ProgramError> {
        // Writable check via verify helper (Kani-provable)
        if !crate::verify::writable_ok(ai.is_writable) {
            return Err(PercolatorError::ExpectedWritable.into());
        }
        Ok(())
    }

    pub fn expect_owner(ai: &AccountInfo, owner: &Pubkey) -> Result<(), ProgramError> {
        if ai.owner != owner {
            return Err(ProgramError::IllegalOwner);
        }
        Ok(())
    }

    pub fn expect_key(ai: &AccountInfo, expected: &Pubkey) -> Result<(), ProgramError> {
        // Key check via verify helper (Kani-provable)
        if !crate::verify::pda_key_matches(expected.to_bytes(), ai.key.to_bytes()) {
            return Err(ProgramError::InvalidArgument);
        }
        Ok(())
    }

    pub fn derive_vault_authority(program_id: &Pubkey, slab_key: &Pubkey) -> (Pubkey, u8) {
        Pubkey::find_program_address(&[b"vault", slab_key.as_ref()], program_id)
    }
}

// 6. mod state
pub mod state {
    use crate::constants::{CONFIG_LEN, HEADER_LEN};
    use crate::bytemuck::{Pod, Zeroable};
    use core::cell::RefMut;
    // use core::mem::offset_of;
    use crate::solana_program::account_info::AccountInfo;
    use crate::solana_program::program_error::ProgramError;

    #[repr(C)]
    #[derive(Clone, Copy, Pod, Zeroable)]
    pub struct SlabHeader {
        pub magic: u64,
        pub version: u32,
        pub bump: u8,
        pub _padding: [u8; 3],
        pub admin: [u8; 32],
        pub _reserved: [u8; 24], // [0..8]=nonce, [8..16]=last_thr_slot, [16..24]=dust_base
    }

    /// Offset of _reserved field in SlabHeader, derived from offset_of! for correctness.
    pub const RESERVED_OFF: usize = 48;

    // Portable compile-time assertion that RESERVED_OFF is 48 (expected layout)
    const _: [(); 48] = [(); RESERVED_OFF];

    #[repr(C)]
    #[derive(Clone, Copy, Pod, Zeroable)]
    pub struct MarketConfig {
        pub collateral_mint: [u8; 32],
        pub vault_pubkey: [u8; 32],
        /// Pyth feed ID for the index price feed
        pub index_feed_id: [u8; 32],
        /// Maximum staleness in seconds (Pyth Pull uses unix timestamps)
        pub max_staleness_secs: u64,
        pub conf_filter_bps: u16,
        pub vault_authority_bump: u8,
        /// If non-zero, invert the oracle price (raw -> 1e12/raw)
        pub invert: u8,
        /// Lamports per Unit for conversion (e.g., 1000 means 1 SOL = 1,000,000 Units)
        /// If 0, no scaling is applied (1:1 lamports to units)
        pub unit_scale: u32,

        // ========================================
        // Funding Parameters (configurable)
        // ========================================
        /// Funding horizon in slots (~4 min at 500 slots)
        pub funding_horizon_slots: u64,
        /// Funding rate multiplier in basis points (100 = 1.00x)
        pub funding_k_bps: u64,
        /// Funding scale factor in e6 units (controls funding rate sensitivity)
        pub funding_inv_scale_notional_e6: u128,
        /// Max premium in basis points (500 = 5%)
        pub funding_max_premium_bps: i64,
        /// Max funding rate per slot in basis points
        pub funding_max_bps_per_slot: i64,

        // ========================================
        // Threshold Parameters (configurable)
        // ========================================
        /// Floor for threshold calculation
        pub thresh_floor: u128,
        /// Risk coefficient in basis points (50 = 0.5%)
        pub thresh_risk_bps: u64,
        /// Update interval in slots
        pub thresh_update_interval_slots: u64,
        /// Max step size in basis points (500 = 5%)
        pub thresh_step_bps: u64,
        /// EWMA alpha in basis points (1000 = 10%)
        pub thresh_alpha_bps: u64,
        /// Minimum threshold value
        pub thresh_min: u128,
        /// Maximum threshold value
        pub thresh_max: u128,
        /// Minimum step size
        pub thresh_min_step: u128,

        // ========================================
        // Oracle Authority (optional signer-based oracle)
        // ========================================
        /// Oracle price authority pubkey. If non-zero, this signer can push prices
        /// directly instead of requiring Pyth/Chainlink. All zeros = disabled.
        pub oracle_authority: [u8; 32],
        /// Last price pushed by oracle authority (in e6 format, already scaled)
        pub authority_price_e6: u64,
        /// Unix timestamp when authority last pushed the price
        pub authority_timestamp: i64,

        // ========================================
        // Oracle Price Circuit Breaker
        // ========================================
        /// Max oracle price change per update in 0.01 bps (e2bps).
        /// 0 = disabled (no cap). 1_000_000 = 100%.
        pub oracle_price_cap_e2bps: u64,
        /// Last effective oracle price (after clamping), in e6 format.
        /// 0 = no history (first price accepted as-is).
        pub last_effective_price_e6: u64,
    }

    pub fn slab_data_mut<'a, 'b>(
        ai: &'b AccountInfo<'a>,
    ) -> Result<RefMut<'b, &'a mut [u8]>, ProgramError> {
        Ok(ai.try_borrow_mut_data()?)
    }

    pub fn read_header(data: &[u8]) -> SlabHeader {
        let mut h = SlabHeader::zeroed();
        let src = &data[..HEADER_LEN];
        let dst = crate::bytemuck::bytes_of_mut(&mut h);
        dst.copy_from_slice(src);
        h
    }

    pub fn write_header(data: &mut [u8], h: &SlabHeader) {
        let src = crate::bytemuck::bytes_of(h);
        let dst = &mut data[..HEADER_LEN];
        dst.copy_from_slice(src);
    }

    /// Read the request nonce from the reserved field in slab header.
    /// The nonce is stored at RESERVED_OFF..RESERVED_OFF+8 as little-endian u64.
    pub fn read_req_nonce(data: &[u8]) -> u64 {
        u64::from_le_bytes(data[RESERVED_OFF..RESERVED_OFF + 8].try_into().unwrap())
    }

    /// Write the request nonce to the reserved field in slab header.
    /// The nonce is stored in _reserved[0..8] as little-endian u64.
    /// Uses offset_of! for correctness even if SlabHeader layout changes.
    pub fn write_req_nonce(data: &mut [u8], nonce: u64) {
        #[cfg(debug_assertions)]
        debug_assert!(HEADER_LEN >= RESERVED_OFF + 16);
        data[RESERVED_OFF..RESERVED_OFF + 8].copy_from_slice(&nonce.to_le_bytes());
    }

    /// Read the last threshold update slot from _reserved[8..16].
    pub fn read_last_thr_update_slot(data: &[u8]) -> u64 {
        u64::from_le_bytes(
            data[RESERVED_OFF + 8..RESERVED_OFF + 16]
                .try_into()
                .unwrap(),
        )
    }

    /// Write the last threshold update slot to _reserved[8..16].
    pub fn write_last_thr_update_slot(data: &mut [u8], slot: u64) {
        data[RESERVED_OFF + 8..RESERVED_OFF + 16].copy_from_slice(&slot.to_le_bytes());
    }

    /// Read accumulated dust (base token remainder) from _reserved[16..24].
    pub fn read_dust_base(data: &[u8]) -> u64 {
        u64::from_le_bytes(
            data[RESERVED_OFF + 16..RESERVED_OFF + 24]
                .try_into()
                .unwrap(),
        )
    }

    /// Write accumulated dust (base token remainder) to _reserved[16..24].
    pub fn write_dust_base(data: &mut [u8], dust: u64) {
        data[RESERVED_OFF + 16..RESERVED_OFF + 24].copy_from_slice(&dust.to_le_bytes());
    }

    // ========================================
    // Market Flags (stored in _padding[0] at offset 13)
    // ========================================

    /// Offset of flags byte in SlabHeader (_padding[0])
    pub const FLAGS_OFF: usize = 13;

    /// Flag bit: Market is resolved (withdraw-only mode)
    pub const FLAG_RESOLVED: u8 = 1 << 0;

    /// Read market flags from _padding[0].
    pub fn read_flags(data: &[u8]) -> u8 {
        data[FLAGS_OFF]
    }

    /// Write market flags to _padding[0].
    pub fn write_flags(data: &mut [u8], flags: u8) {
        data[FLAGS_OFF] = flags;
    }

    /// Check if market is resolved (withdraw-only mode).
    pub fn is_resolved(data: &[u8]) -> bool {
        read_flags(data) & FLAG_RESOLVED != 0
    }

    /// Set the resolved flag.
    pub fn set_resolved(data: &mut [u8]) {
        let flags = read_flags(data) | FLAG_RESOLVED;
        write_flags(data, flags);
    }

    pub fn read_config(data: &[u8]) -> MarketConfig {
        let mut c = MarketConfig::zeroed();
        let src = &data[HEADER_LEN..HEADER_LEN + CONFIG_LEN];
        let dst = crate::bytemuck::bytes_of_mut(&mut c);
        dst.copy_from_slice(src);
        c
    }

    pub fn write_config(data: &mut [u8], c: &MarketConfig) {
        let src = crate::bytemuck::bytes_of(c);
        let dst = &mut data[HEADER_LEN..HEADER_LEN + CONFIG_LEN];
        dst.copy_from_slice(src);
    }
}

// 7. mod units - base token/units conversion at instruction boundaries
pub mod units {
    /// Convert base token amount to units, returning (units, dust).
    /// Base token is the collateral (e.g., lamports for SOL, satoshis for BTC).
    /// If scale is 0, returns (base, 0) - no scaling.
    #[inline]
    pub fn base_to_units(base: u64, scale: u32) -> (u64, u64) {
        if scale == 0 {
            return (base, 0);
        }
        let s = scale as u64;
        (base / s, base % s)
    }

    /// Convert units to base token amount.
    /// If scale is 0, returns units unchanged - no scaling.
    #[inline]
    pub fn units_to_base(units: u64, scale: u32) -> u64 {
        if scale == 0 {
            return units;
        }
        units.saturating_mul(scale as u64)
    }

    /// Convert units to base token amount with overflow check.
    /// Returns None if overflow would occur.
    #[inline]
    pub fn units_to_base_checked(units: u64, scale: u32) -> Option<u64> {
        if scale == 0 {
            return Some(units);
        }
        units.checked_mul(scale as u64)
    }
}

// 8. mod oracle
pub mod oracle {
    use crate::error::PercolatorError;
    use crate::solana_program::{account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey};

    // SECURITY (H5): The "devnet" feature disables critical oracle safety checks:
    // - Staleness validation (stale prices accepted)
    // - Confidence interval validation (wide confidence accepted)
    //
    // WARNING: NEVER deploy to mainnet with the "devnet" feature enabled!
    // Build for mainnet with: cargo build-sbf (without --features devnet)

    /// Pyth Solana Receiver program ID (same for mainnet and devnet)
    /// rec5EKMGg6MxZYaMdyBfgwp4d5rB9T1VQH5pJv5LtFJ
    pub const PYTH_RECEIVER_PROGRAM_ID: Pubkey = Pubkey::new_from_array([
        0x0c, 0xb7, 0xfa, 0xbb, 0x52, 0xf7, 0xa6, 0x48, 0xbb, 0x5b, 0x31, 0x7d, 0x9a, 0x01, 0x8b,
        0x90, 0x57, 0xcb, 0x02, 0x47, 0x74, 0xfa, 0xfe, 0x01, 0xe6, 0xc4, 0xdf, 0x98, 0xcc, 0x38,
        0x58, 0x81,
    ]);

    /// Chainlink OCR2 Store program ID (same for mainnet and devnet)
    /// HEvSKofvBgfaexv23kMabbYqxasxU3mQ4ibBMEmJWHny
    pub const CHAINLINK_OCR2_PROGRAM_ID: Pubkey = Pubkey::new_from_array([
        0xf1, 0x4b, 0xf6, 0x5a, 0xd5, 0x6b, 0xd2, 0xba, 0x71, 0x5e, 0x45, 0x74, 0x2c, 0x23, 0x1f,
        0x27, 0xd6, 0x36, 0x21, 0xcf, 0x5b, 0x77, 0x8f, 0x37, 0xc1, 0xa2, 0x48, 0x95, 0x1d, 0x17,
        0x56, 0x02,
    ]);

    // PriceUpdateV2 account layout offsets (134 bytes minimum)
    // See: https://github.com/pyth-network/pyth-crosschain/blob/main/target_chains/solana/pyth_solana_receiver_sdk/src/price_update.rs
    const PRICE_UPDATE_V2_MIN_LEN: usize = 134;
    const OFF_FEED_ID: usize = 42; // 32 bytes
    const OFF_PRICE: usize = 74; // i64
    const OFF_CONF: usize = 82; // u64
    const OFF_EXPO: usize = 90; // i32
    const OFF_PUBLISH_TIME: usize = 94; // i64

    // Chainlink OCR2 State/Aggregator account layout offsets (devnet format)
    // This is the simpler account format used on Solana devnet
    // Note: Different from the Transmissions ring buffer format in older docs
    const CL_MIN_LEN: usize = 224; // Minimum required length
    const CL_OFF_DECIMALS: usize = 138; // u8 - number of decimals
                                        // Skip unused: latest_round_id (143), live_length (148), live_cursor (152)
                                        // The actual price data is stored directly at tail:
    const CL_OFF_SLOT: usize = 200; // u64 - slot when updated
    const CL_OFF_TIMESTAMP: usize = 208; // u64 - unix timestamp (seconds)
    const CL_OFF_ANSWER: usize = 216; // i128 - price answer

    // Maximum supported exponent to prevent overflow (10^18 fits in u128)
    const MAX_EXPO_ABS: i32 = 18;

    /// Read price from a Pyth PriceUpdateV2 account.
    ///
    /// Parameters:
    /// - price_ai: The PriceUpdateV2 account
    /// - expected_feed_id: The expected Pyth feed ID (must match account's feed_id)
    /// - now_unix_ts: Current unix timestamp (from clock.unix_timestamp)
    /// - max_staleness_secs: Maximum age in seconds
    /// - conf_bps: Maximum confidence interval in basis points
    ///
    /// Returns the price in e6 format (e.g., 150_000_000 = 150.00 in base units).
    pub fn read_pyth_price_e6(
        price_ai: &AccountInfo,
        expected_feed_id: &[u8; 32],
        now_unix_ts: i64,
        max_staleness_secs: u64,
        conf_bps: u16,
    ) -> Result<u64, ProgramError> {
        // Validate oracle owner (skip in tests to allow mock oracles)
        #[cfg(not(feature = "test"))]
        {
            if *price_ai.owner != PYTH_RECEIVER_PROGRAM_ID {
                return Err(ProgramError::IllegalOwner);
            }
        }

        let data = price_ai.try_borrow_data()?;
        if data.len() < PRICE_UPDATE_V2_MIN_LEN {
            return Err(ProgramError::InvalidAccountData);
        }

        // Validate feed_id matches expected
        let feed_id: [u8; 32] = data[OFF_FEED_ID..OFF_FEED_ID + 32].try_into().unwrap();
        if &feed_id != expected_feed_id {
            return Err(PercolatorError::InvalidOracleKey.into());
        }

        // Read price fields
        let price = i64::from_le_bytes(data[OFF_PRICE..OFF_PRICE + 8].try_into().unwrap());
        let conf = u64::from_le_bytes(data[OFF_CONF..OFF_CONF + 8].try_into().unwrap());
        let expo = i32::from_le_bytes(data[OFF_EXPO..OFF_EXPO + 4].try_into().unwrap());
        let publish_time = i64::from_le_bytes(
            data[OFF_PUBLISH_TIME..OFF_PUBLISH_TIME + 8]
                .try_into()
                .unwrap(),
        );

        if price <= 0 {
            return Err(PercolatorError::OracleInvalid.into());
        }

        // SECURITY (C3): Bound exponent to prevent overflow in pow()
        if expo.abs() > MAX_EXPO_ABS {
            return Err(PercolatorError::OracleInvalid.into());
        }

        // Staleness check (skip on devnet)
        #[cfg(not(feature = "devnet"))]
        {
            let age = now_unix_ts.saturating_sub(publish_time);
            if age < 0 || age as u64 > max_staleness_secs {
                return Err(PercolatorError::OracleStale.into());
            }
        }
        #[cfg(feature = "devnet")]
        let _ = (publish_time, max_staleness_secs, now_unix_ts);

        // Confidence check (skip on devnet)
        let price_u = price as u128;
        #[cfg(not(feature = "devnet"))]
        {
            let lhs = (conf as u128) * 10_000;
            let rhs = price_u * (conf_bps as u128);
            if lhs > rhs {
                return Err(PercolatorError::OracleConfTooWide.into());
            }
        }
        #[cfg(feature = "devnet")]
        let _ = (conf, conf_bps);

        // Convert to e6 format
        let scale = expo + 6;
        let final_price_u128 = if scale >= 0 {
            let mul = 10u128.pow(scale as u32);
            price_u
                .checked_mul(mul)
                .ok_or(PercolatorError::EngineOverflow)?
        } else {
            let div = 10u128.pow((-scale) as u32);
            price_u / div
        };

        if final_price_u128 == 0 {
            return Err(PercolatorError::OracleInvalid.into());
        }
        if final_price_u128 > u64::MAX as u128 {
            return Err(PercolatorError::EngineOverflow.into());
        }

        Ok(final_price_u128 as u64)
    }

    /// Read price from a Chainlink OCR2 State/Aggregator account.
    ///
    /// Parameters:
    /// - price_ai: The Chainlink aggregator account
    /// - expected_feed_pubkey: The expected feed account pubkey (for validation)
    /// - now_unix_ts: Current unix timestamp (from clock.unix_timestamp)
    /// - max_staleness_secs: Maximum age in seconds
    ///
    /// Returns the price in e6 format (e.g., 150_000_000 = 150.00 in base units).
    /// Note: Chainlink doesn't have confidence intervals, so conf_bps is not used.
    pub fn read_chainlink_price_e6(
        price_ai: &AccountInfo,
        expected_feed_pubkey: &[u8; 32],
        now_unix_ts: i64,
        max_staleness_secs: u64,
    ) -> Result<u64, ProgramError> {
        // Validate oracle owner (skip in tests to allow mock oracles)
        #[cfg(not(feature = "test"))]
        {
            if *price_ai.owner != CHAINLINK_OCR2_PROGRAM_ID {
                return Err(ProgramError::IllegalOwner);
            }
        }

        // Validate feed pubkey matches expected
        if price_ai.key.to_bytes() != *expected_feed_pubkey {
            return Err(PercolatorError::InvalidOracleKey.into());
        }

        let data = price_ai.try_borrow_data()?;
        if data.len() < CL_MIN_LEN {
            return Err(ProgramError::InvalidAccountData);
        }

        // Read header fields
        let decimals = data[CL_OFF_DECIMALS];

        // Read price data directly from fixed offsets
        let timestamp = u64::from_le_bytes(
            data[CL_OFF_TIMESTAMP..CL_OFF_TIMESTAMP + 8]
                .try_into()
                .unwrap(),
        );
        // Read answer as i128 (16 bytes), but only bottom 8 bytes are typically used
        let answer =
            i128::from_le_bytes(data[CL_OFF_ANSWER..CL_OFF_ANSWER + 16].try_into().unwrap());

        if answer <= 0 {
            return Err(PercolatorError::OracleInvalid.into());
        }

        // SECURITY (C3): Bound decimals to prevent overflow in pow()
        if decimals > MAX_EXPO_ABS as u8 {
            return Err(PercolatorError::OracleInvalid.into());
        }

        // Staleness check (skip on devnet)
        #[cfg(not(feature = "devnet"))]
        {
            let age = now_unix_ts.saturating_sub(timestamp as i64);
            if age < 0 || age as u64 > max_staleness_secs {
                return Err(PercolatorError::OracleStale.into());
            }
        }
        #[cfg(feature = "devnet")]
        let _ = (timestamp, max_staleness_secs, now_unix_ts);

        // Convert to e6 format
        // Chainlink decimals work like: price = answer / 10^decimals
        // We want e6, so: price_e6 = answer * 10^6 / 10^decimals = answer * 10^(6-decimals)
        let price_u = answer as u128;
        let scale = 6i32 - decimals as i32;
        let final_price_u128 = if scale >= 0 {
            let mul = 10u128.pow(scale as u32);
            price_u
                .checked_mul(mul)
                .ok_or(PercolatorError::EngineOverflow)?
        } else {
            let div = 10u128.pow((-scale) as u32);
            price_u / div
        };

        if final_price_u128 == 0 {
            return Err(PercolatorError::OracleInvalid.into());
        }
        if final_price_u128 > u64::MAX as u128 {
            return Err(PercolatorError::EngineOverflow.into());
        }

        Ok(final_price_u128 as u64)
    }

    /// Read oracle price for engine use, applying inversion and unit scaling if configured.
    ///
    /// Automatically detects oracle type by account owner:
    /// - PYTH_RECEIVER_PROGRAM_ID: reads Pyth PriceUpdateV2
    /// - CHAINLINK_OCR2_PROGRAM_ID: reads Chainlink OCR2 Transmissions
    ///
    /// Transformations applied in order:
    /// 1. If invert != 0: inverted price = 1e12 / raw_e6
    /// 2. If unit_scale > 1: scaled price = price / unit_scale
    ///
    /// CRITICAL: The unit_scale transformation ensures oracle-derived values (entry_price,
    /// mark_pnl, position_value) are in the same scale as capital (which is stored in units).
    /// Without this scaling, margin checks would compare units to base tokens incorrectly.
    ///
    /// The raw oracle is validated (staleness, confidence for Pyth) BEFORE transformations.
    pub fn read_engine_price_e6(
        price_ai: &AccountInfo,
        expected_feed_id: &[u8; 32],
        now_unix_ts: i64,
        max_staleness_secs: u64,
        conf_bps: u16,
        invert: u8,
        unit_scale: u32,
    ) -> Result<u64, ProgramError> {
        // Detect oracle type by account owner and dispatch
        let raw_price = if *price_ai.owner == PYTH_RECEIVER_PROGRAM_ID {
            read_pyth_price_e6(
                price_ai,
                expected_feed_id,
                now_unix_ts,
                max_staleness_secs,
                conf_bps,
            )?
        } else if *price_ai.owner == CHAINLINK_OCR2_PROGRAM_ID {
            read_chainlink_price_e6(price_ai, expected_feed_id, now_unix_ts, max_staleness_secs)?
        } else {
            // In test mode, try Pyth format first (for existing tests)
            #[cfg(feature = "test")]
            {
                read_pyth_price_e6(
                    price_ai,
                    expected_feed_id,
                    now_unix_ts,
                    max_staleness_secs,
                    conf_bps,
                )?
            }
            #[cfg(not(feature = "test"))]
            {
                return Err(ProgramError::IllegalOwner);
            }
        };

        // Step 1: Apply inversion if configured (uses verify::invert_price_e6)
        let price_after_invert = crate::verify::invert_price_e6(raw_price, invert)
            .ok_or(PercolatorError::OracleInvalid)?;

        // Step 2: Apply unit scaling if configured (uses verify::scale_price_e6)
        // This ensures oracle-derived values match capital scale (stored in units)
        crate::verify::scale_price_e6(price_after_invert, unit_scale)
            .ok_or(PercolatorError::OracleInvalid.into())
    }

    /// Check if authority-pushed price is available and fresh.
    /// Returns Some(price_e6) if authority is set and price is within staleness bounds.
    /// Returns None if no authority is set or price is stale.
    ///
    /// Note: The stored authority_price_e6 is already in the correct format (e6, scaled).
    pub fn read_authority_price(
        config: &super::state::MarketConfig,
        now_unix_ts: i64,
        max_staleness_secs: u64,
    ) -> Option<u64> {
        // No authority set
        if config.oracle_authority == [0u8; 32] {
            return None;
        }
        // No price pushed yet
        if config.authority_price_e6 == 0 {
            return None;
        }
        // Check staleness
        let age = now_unix_ts.saturating_sub(config.authority_timestamp);
        if age < 0 || age as u64 > max_staleness_secs {
            return None;
        }
        Some(config.authority_price_e6)
    }

    /// Read oracle price, preferring authority-pushed price over Pyth/Chainlink.
    ///
    /// If an oracle authority is configured and has pushed a fresh price, use that.
    /// Otherwise, fall back to reading from the provided Pyth/Chainlink account.
    ///
    /// The price_ai can be any account when using authority oracle - it won't be read
    /// if the authority price is valid.
    pub fn read_price_with_authority(
        config: &super::state::MarketConfig,
        price_ai: &AccountInfo,
        now_unix_ts: i64,
    ) -> Result<u64, ProgramError> {
        // Try authority price first
        if let Some(authority_price) =
            read_authority_price(config, now_unix_ts, config.max_staleness_secs)
        {
            return Ok(authority_price);
        }

        // Fall back to Pyth/Chainlink
        read_engine_price_e6(
            price_ai,
            &config.index_feed_id,
            now_unix_ts,
            config.max_staleness_secs,
            config.conf_filter_bps,
            config.invert,
            config.unit_scale,
        )
    }

    /// Clamp `raw_price` so it cannot move more than `max_change_e2bps` from `last_price`.
    /// Units: 1_000_000 e2bps = 100%. 0 = disabled (no cap). last_price == 0 = first-time.
    pub fn clamp_oracle_price(last_price: u64, raw_price: u64, max_change_e2bps: u64) -> u64 {
        if max_change_e2bps == 0 || last_price == 0 {
            return raw_price;
        }
        let max_delta = ((last_price as u128) * (max_change_e2bps as u128) / 1_000_000) as u64;
        let lower = last_price.saturating_sub(max_delta);
        let upper = last_price.saturating_add(max_delta);
        raw_price.clamp(lower, upper)
    }

    /// Read oracle price with circuit-breaker clamping.
    /// Reads raw price via `read_price_with_authority`, clamps it against
    /// `config.last_effective_price_e6`, and updates that field to the post-clamped value.
    pub fn read_price_clamped(
        config: &mut super::state::MarketConfig,
        price_ai: &AccountInfo,
        now_unix_ts: i64,
    ) -> Result<u64, ProgramError> {
        let raw = read_price_with_authority(config, price_ai, now_unix_ts)?;
        let clamped = clamp_oracle_price(
            config.last_effective_price_e6,
            raw,
            config.oracle_price_cap_e2bps,
        );
        config.last_effective_price_e6 = clamped;
        Ok(clamped)
    }

    // =========================================================================
    // Hyperp mode helpers (internal mark/index, no external oracle)
    // =========================================================================

    /// Check if Hyperp mode is active (internal mark/index pricing).
    /// Hyperp mode is active when index_feed_id is all zeros.
    #[inline]
    pub fn is_hyperp_mode(config: &super::state::MarketConfig) -> bool {
        config.index_feed_id == [0u8; 32]
    }

    /// Move `index` toward `mark`, but clamp movement by cap_e2bps * dt_slots.
    /// cap_e2bps units: 1_000_000 = 100.00%
    /// Returns the new index value.
    ///
    /// Security: When dt_slots == 0 (same slot) or cap_e2bps == 0 (cap disabled),
    /// returns index unchanged to prevent bypassing rate limits.
    pub fn clamp_toward_with_dt(index: u64, mark: u64, cap_e2bps: u64, dt_slots: u64) -> u64 {
        if index == 0 {
            return mark;
        }
        // Bug #9 fix: return index (no movement) when dt=0 or cap=0,
        // rather than mark (bypass rate limiting)
        if cap_e2bps == 0 || dt_slots == 0 {
            return index;
        }

        let max_delta_u128 = (index as u128)
            .saturating_mul(cap_e2bps as u128)
            .saturating_mul(dt_slots as u128)
            / 1_000_000u128;

        let max_delta = core::cmp::min(max_delta_u128, u64::MAX as u128) as u64;
        let lo = index.saturating_sub(max_delta);
        let hi = index.saturating_add(max_delta);
        mark.clamp(lo, hi)
    }

    /// Get engine oracle price (unified: external oracle vs Hyperp mode).
    /// In Hyperp mode: updates index toward mark with rate limiting.
    /// In external mode: reads from Pyth/Chainlink/authority with circuit breaker.
    pub fn get_engine_oracle_price_e6(
        engine_last_slot: u64,
        now_slot: u64,
        now_unix_ts: i64,
        config: &mut super::state::MarketConfig,
        a_oracle: &AccountInfo,
    ) -> Result<u64, ProgramError> {
        // Hyperp mode: index_feed_id == 0
        if is_hyperp_mode(config) {
            let mark = config.authority_price_e6;
            if mark == 0 {
                return Err(super::error::PercolatorError::OracleInvalid.into());
            }

            let prev_index = config.last_effective_price_e6;
            let dt = now_slot.saturating_sub(engine_last_slot);
            let new_index =
                clamp_toward_with_dt(prev_index.max(1), mark, config.oracle_price_cap_e2bps, dt);

            config.last_effective_price_e6 = new_index;
            return Ok(new_index);
        }

        // Non-Hyperp: existing behavior (authority -> Pyth/Chainlink) + circuit breaker
        read_price_clamped(config, a_oracle, now_unix_ts)
    }

    /// Compute premium-based funding rate (Hyperp funding model).
    /// Premium = (mark - index) / index, converted to bps per slot.
    /// Returns signed bps per slot (positive = longs pay shorts).
    pub fn compute_premium_funding_bps_per_slot(
        mark_e6: u64,
        index_e6: u64,
        funding_horizon_slots: u64,
        funding_k_bps: u64,   // 100 = 1.00x multiplier
        max_premium_bps: i64, // e.g. 500 = 5%
        max_bps_per_slot: i64,
    ) -> i64 {
        if mark_e6 == 0 || index_e6 == 0 || funding_horizon_slots == 0 {
            return 0;
        }

        let diff = mark_e6 as i128 - index_e6 as i128;
        let mut premium_bps = diff.saturating_mul(10_000) / (index_e6 as i128);

        // Clamp premium
        premium_bps = premium_bps.clamp(-(max_premium_bps as i128), max_premium_bps as i128);

        // Apply k multiplier (100 => 1.00x)
        let scaled = premium_bps.saturating_mul(funding_k_bps as i128) / 100i128;

        // Convert to per-slot by dividing by horizon
        let mut per_slot = (scaled / (funding_horizon_slots as i128)) as i64;

        // Policy clamp
        per_slot = per_slot.clamp(-max_bps_per_slot, max_bps_per_slot);
        per_slot
    }
}

// 9. mod collateral
pub mod collateral {
    use crate::solana_program::{account_info::AccountInfo, program_error::ProgramError};

    #[cfg(not(feature = "test"))]
    use crate::solana_program::program::{invoke, invoke_signed};

    #[cfg(feature = "test")]
    use crate::solana_program::program_pack::Pack;
    #[cfg(feature = "test")]
    use spl_token::state::Account as TokenAccount;

    pub fn deposit<'a>(
        _token_program: &AccountInfo<'a>,
        source: &AccountInfo<'a>,
        dest: &AccountInfo<'a>,
        _authority: &AccountInfo<'a>,
        amount: u64,
    ) -> Result<(), ProgramError> {
        if amount == 0 {
            return Ok(());
        }
        #[cfg(not(feature = "test"))]
        {
            let ix = spl_token::instruction::transfer(
                _token_program.key,
                source.key,
                dest.key,
                _authority.key,
                &[],
                amount,
            )?;
            invoke(
                &ix,
                &[
                    source.clone(),
                    dest.clone(),
                    _authority.clone(),
                    _token_program.clone(),
                ],
            )
        }
        #[cfg(feature = "test")]
        {
            let mut src_data = source.try_borrow_mut_data()?;
            let mut src_state = TokenAccount::unpack(&src_data)?;
            src_state.amount = src_state
                .amount
                .checked_sub(amount)
                .ok_or(ProgramError::InsufficientFunds)?;
            TokenAccount::pack(src_state, &mut src_data)?;

            let mut dst_data = dest.try_borrow_mut_data()?;
            let mut dst_state = TokenAccount::unpack(&dst_data)?;
            dst_state.amount = dst_state
                .amount
                .checked_add(amount)
                .ok_or(ProgramError::InvalidAccountData)?;
            TokenAccount::pack(dst_state, &mut dst_data)?;
            Ok(())
        }
    }

    pub fn withdraw<'a>(
        _token_program: &AccountInfo<'a>,
        source: &AccountInfo<'a>,
        dest: &AccountInfo<'a>,
        _authority: &AccountInfo<'a>,
        amount: u64,
        _signer_seeds: &[&[&[u8]]],
    ) -> Result<(), ProgramError> {
        if amount == 0 {
            return Ok(());
        }
        #[cfg(not(feature = "test"))]
        {
            let ix = spl_token::instruction::transfer(
                _token_program.key,
                source.key,
                dest.key,
                _authority.key,
                &[],
                amount,
            )?;
            invoke_signed(
                &ix,
                &[
                    source.clone(),
                    dest.clone(),
                    _authority.clone(),
                    _token_program.clone(),
                ],
                _signer_seeds,
            )
        }
        #[cfg(feature = "test")]
        {
            let mut src_data = source.try_borrow_mut_data()?;
            let mut src_state = TokenAccount::unpack(&src_data)?;
            src_state.amount = src_state
                .amount
                .checked_sub(amount)
                .ok_or(ProgramError::InsufficientFunds)?;
            TokenAccount::pack(src_state, &mut src_data)?;

            let mut dst_data = dest.try_borrow_mut_data()?;
            let mut dst_state = TokenAccount::unpack(&dst_data)?;
            dst_state.amount = dst_state
                .amount
                .checked_add(amount)
                .ok_or(ProgramError::InvalidAccountData)?;
            TokenAccount::pack(dst_state, &mut dst_data)?;
            Ok(())
        }
    }
}

// 9. mod processor
pub mod processor {
    use crate::{
        accounts, collateral,
        constants::{
            CONFIG_LEN, DEFAULT_FUNDING_HORIZON_SLOTS, DEFAULT_FUNDING_INV_SCALE_NOTIONAL_E6,
            DEFAULT_FUNDING_K_BPS, DEFAULT_FUNDING_MAX_BPS_PER_SLOT,
            DEFAULT_FUNDING_MAX_PREMIUM_BPS, DEFAULT_HYPERP_PRICE_CAP_E2BPS,
            DEFAULT_THRESH_ALPHA_BPS, DEFAULT_THRESH_FLOOR, DEFAULT_THRESH_MAX, DEFAULT_THRESH_MIN,
            DEFAULT_THRESH_MIN_STEP, DEFAULT_THRESH_RISK_BPS, DEFAULT_THRESH_STEP_BPS,
            DEFAULT_THRESH_UPDATE_INTERVAL_SLOTS, MAGIC, MATCHER_CALL_LEN, MATCHER_CALL_TAG,
            MATCHER_CONTEXT_LEN, MATCHER_CONTEXT_PREFIX_LEN, SLAB_LEN, VERSION,
        },
        error::{map_risk_error, PercolatorError},
        ix::Instruction,
        oracle,
        state::{self, MarketConfig, SlabHeader},
        zc,
    };
    use crate::percolator::{
        MatchingEngine, NoOpMatcher, RiskEngine, RiskError, TradeExecution, MAX_ACCOUNTS,
    };
    use crate::solana_program::instruction::{AccountMeta, Instruction as SolInstruction};
    use crate::solana_program::{
        account_info::AccountInfo,
        entrypoint::ProgramResult,
        log::{sol_log_64, sol_log_compute_units},
        msg,
        program_error::ProgramError,
        program_pack::Pack,
        pubkey::Pubkey,
        sysvar::{clock::Clock, Sysvar},
    };

    struct CpiMatcher {
        exec_price: u64,
        exec_size: i128,
    }

    impl MatchingEngine for CpiMatcher {
        fn execute_match(
            &self,
            _lp_program: &[u8; 32],
            _lp_context: &[u8; 32],
            _lp_account_id: u64,
            _oracle_price: u64,
            _size: i128,
        ) -> Result<TradeExecution, RiskError> {
            Ok(TradeExecution {
                price: self.exec_price,
                size: self.exec_size,
            })
        }
    }

    fn slab_guard(
        program_id: &Pubkey,
        slab: &AccountInfo,
        data: &[u8],
    ) -> Result<(), ProgramError> {
        // Slab shape validation via verify helper (Kani-provable)
        // Accept old slabs that are 8 bytes smaller due to Account struct reordering migration.
        // Old slabs (1111384 bytes) work for up to 4095 accounts; new slabs (1111392) for 4096.
        const OLD_SLAB_LEN: usize = SLAB_LEN - 8;
        let shape = crate::verify::SlabShape {
            owned_by_program: slab.owner == program_id,
            correct_len: data.len() == SLAB_LEN || data.len() == OLD_SLAB_LEN,
        };
        if !crate::verify::slab_shape_ok(shape) {
            // Return specific error based on which check failed
            if slab.owner != program_id {
                return Err(ProgramError::IllegalOwner);
            }
            crate::solana_program::log::sol_log_64(SLAB_LEN as u64, data.len() as u64, 0, 0, 0);
            return Err(PercolatorError::InvalidSlabLen.into());
        }
        Ok(())
    }

    fn require_initialized(data: &[u8]) -> Result<(), ProgramError> {
        let h = state::read_header(data);
        if h.magic != MAGIC {
            return Err(PercolatorError::NotInitialized.into());
        }
        if h.version != VERSION {
            return Err(PercolatorError::InvalidVersion.into());
        }
        Ok(())
    }

    /// Require that the signer is the current admin.
    /// If admin is burned (all zeros), admin operations are permanently disabled.
    /// Admin authorization via verify helper (Kani-provable)
    fn require_admin(header_admin: [u8; 32], signer: &Pubkey) -> Result<(), ProgramError> {
        if !crate::verify::admin_ok(header_admin, signer.to_bytes()) {
            return Err(PercolatorError::EngineUnauthorized.into());
        }
        Ok(())
    }

    fn check_idx(engine: &RiskEngine, idx: u16) -> Result<(), ProgramError> {
        if (idx as usize) >= MAX_ACCOUNTS || !engine.is_used(idx as usize) {
            return Err(PercolatorError::EngineAccountNotFound.into());
        }
        Ok(())
    }

    fn verify_vault(
        a_vault: &AccountInfo,
        expected_owner: &Pubkey,
        expected_mint: &Pubkey,
        expected_pubkey: &Pubkey,
    ) -> Result<(), ProgramError> {
        if a_vault.key != expected_pubkey {
            return Err(PercolatorError::InvalidVaultAta.into());
        }
        if a_vault.owner != &spl_token::ID {
            return Err(PercolatorError::InvalidVaultAta.into());
        }
        if a_vault.data_len() != spl_token::state::Account::LEN {
            return Err(PercolatorError::InvalidVaultAta.into());
        }

        let data = a_vault.try_borrow_data()?;
        let tok = spl_token::state::Account::unpack(&data)?;
        if tok.mint != *expected_mint {
            return Err(PercolatorError::InvalidMint.into());
        }
        if tok.owner != *expected_owner {
            return Err(PercolatorError::InvalidVaultAta.into());
        }
        // SECURITY (H3): Verify vault token account is initialized
        // Uninitialized vault could brick deposits/withdrawals
        if tok.state != spl_token::state::AccountState::Initialized {
            return Err(PercolatorError::InvalidVaultAta.into());
        }
        Ok(())
    }

    /// Verify a user's token account: owner, mint, and initialized state.
    /// Skip in tests to allow mock accounts.
    #[allow(unused_variables)]
    fn verify_token_account(
        a_token_account: &AccountInfo,
        expected_owner: &Pubkey,
        expected_mint: &Pubkey,
    ) -> Result<(), ProgramError> {
        #[cfg(not(feature = "test"))]
        {
            if a_token_account.owner != &spl_token::ID {
                return Err(PercolatorError::InvalidTokenAccount.into());
            }
            if a_token_account.data_len() != spl_token::state::Account::LEN {
                return Err(PercolatorError::InvalidTokenAccount.into());
            }

            let data = a_token_account.try_borrow_data()?;
            let tok = spl_token::state::Account::unpack(&data)?;
            if tok.mint != *expected_mint {
                return Err(PercolatorError::InvalidMint.into());
            }
            if tok.owner != *expected_owner {
                return Err(PercolatorError::InvalidTokenAccount.into());
            }
            if tok.state != spl_token::state::AccountState::Initialized {
                return Err(PercolatorError::InvalidTokenAccount.into());
            }
        }
        Ok(())
    }

    /// Verify the token program account is valid.
    /// Skip in tests to allow mock accounts.
    #[allow(unused_variables)]
    fn verify_token_program(a_token: &AccountInfo) -> Result<(), ProgramError> {
        #[cfg(not(feature = "test"))]
        {
            if *a_token.key != spl_token::ID {
                return Err(PercolatorError::InvalidTokenProgram.into());
            }
            if !a_token.executable {
                return Err(PercolatorError::InvalidTokenProgram.into());
            }
        }
        Ok(())
    }

    pub fn process_instruction<'a, 'b>(
        program_id: &Pubkey,
        accounts: &'b [AccountInfo<'a>],
        instruction_data: &[u8],
    ) -> ProgramResult {
        let instruction = Instruction::decode(instruction_data)?;

        match instruction {
            Instruction::InitMarket {
                admin,
                collateral_mint,
                index_feed_id,
                max_staleness_secs,
                conf_filter_bps,
                invert,
                unit_scale,
                initial_mark_price_e6,
                risk_params,
            } => {
                // Reduced from 11 to 9: removed pyth_index and pyth_collateral accounts
                // (feed_id is now passed in instruction data, not as account)
                accounts::expect_len(accounts, 9)?;
                let a_admin = &accounts[0];
                let a_slab = &accounts[1];
                let a_mint = &accounts[2];
                let a_vault = &accounts[3];

                accounts::expect_signer(a_admin)?;
                accounts::expect_writable(a_slab)?;

                // Ensure instruction data matches the signer
                if admin != *a_admin.key {
                    return Err(ProgramError::InvalidInstructionData);
                }

                // SECURITY (H1): Enforce collateral_mint matches the account
                // This prevents signers from being confused by mismatched instruction data
                if collateral_mint != *a_mint.key {
                    return Err(ProgramError::InvalidInstructionData);
                }

                // SECURITY (H2): Validate mint is a real SPL Token mint
                // Check owner == spl_token::ID and data length == Mint::LEN (82 bytes)
                #[cfg(not(feature = "test"))]
                {
                    use crate::solana_program::program_pack::Pack;
                    use spl_token::state::Mint;
                    if *a_mint.owner != spl_token::ID {
                        return Err(ProgramError::IllegalOwner);
                    }
                    if a_mint.data_len() != Mint::LEN {
                        return Err(ProgramError::InvalidAccountData);
                    }
                    // Verify mint is initialized by unpacking
                    let mint_data = a_mint.try_borrow_data()?;
                    let _ = Mint::unpack(&mint_data)?;
                }

                // Validate unit_scale: reject huge values that make most deposits credit 0 units
                if !crate::verify::init_market_scale_ok(unit_scale) {
                    return Err(ProgramError::InvalidInstructionData);
                }

                // Hyperp mode validation: if index_feed_id is all zeros, require initial_mark_price_e6
                let is_hyperp = index_feed_id == [0u8; 32];
                if is_hyperp && initial_mark_price_e6 == 0 {
                    // Hyperp mode requires a non-zero initial mark price
                    return Err(ProgramError::InvalidInstructionData);
                }

                // For Hyperp mode with inverted markets, apply inversion to initial price
                // This ensures the stored mark/index are in "market price" form
                let initial_mark_price_e6 = if is_hyperp && invert != 0 {
                    crate::verify::invert_price_e6(initial_mark_price_e6, invert)
                        .ok_or(PercolatorError::OracleInvalid)?
                } else {
                    initial_mark_price_e6
                };

                #[cfg(debug_assertions)]
                {
                    if core::mem::size_of::<MarketConfig>() != CONFIG_LEN {
                        return Err(ProgramError::InvalidAccountData);
                    }
                }

                let mut data = state::slab_data_mut(a_slab)?;
                slab_guard(program_id, a_slab, &data)?;

                let _ = zc::engine_mut(&mut data)?;

                let header = state::read_header(&data);
                if header.magic == MAGIC {
                    return Err(PercolatorError::AlreadyInitialized.into());
                }

                let (auth, bump) = accounts::derive_vault_authority(program_id, a_slab.key);
                verify_vault(a_vault, &auth, a_mint.key, a_vault.key)?;

                for b in data.iter_mut() {
                    *b = 0;
                }

                // Initialize engine in-place (zero-copy) to avoid stack overflow.
                // The data is already zeroed above, so init_in_place only sets non-zero fields.
                let engine = zc::engine_mut(&mut data)?;
                engine.init_in_place(risk_params);

                // Initialize slot fields to current slot to prevent overflow on first crank
                // (accrue_funding checks dt < 31_536_000, which fails if last_funding_slot=0)
                let a_clock = &accounts[5];
                let clock = Clock::from_account_info(a_clock)?;
                engine.current_slot = clock.slot;
                engine.last_funding_slot = clock.slot;
                engine.last_crank_slot = clock.slot;

                let config = MarketConfig {
                    collateral_mint: a_mint.key.to_bytes(),
                    vault_pubkey: a_vault.key.to_bytes(),
                    index_feed_id,
                    max_staleness_secs,
                    conf_filter_bps,
                    vault_authority_bump: bump,
                    invert,
                    unit_scale,
                    // Funding parameters (defaults)
                    funding_horizon_slots: DEFAULT_FUNDING_HORIZON_SLOTS,
                    funding_k_bps: DEFAULT_FUNDING_K_BPS,
                    funding_inv_scale_notional_e6: DEFAULT_FUNDING_INV_SCALE_NOTIONAL_E6,
                    funding_max_premium_bps: DEFAULT_FUNDING_MAX_PREMIUM_BPS,
                    funding_max_bps_per_slot: DEFAULT_FUNDING_MAX_BPS_PER_SLOT,
                    // Threshold parameters (defaults)
                    thresh_floor: DEFAULT_THRESH_FLOOR,
                    thresh_risk_bps: DEFAULT_THRESH_RISK_BPS,
                    thresh_update_interval_slots: DEFAULT_THRESH_UPDATE_INTERVAL_SLOTS,
                    thresh_step_bps: DEFAULT_THRESH_STEP_BPS,
                    thresh_alpha_bps: DEFAULT_THRESH_ALPHA_BPS,
                    thresh_min: DEFAULT_THRESH_MIN,
                    thresh_max: DEFAULT_THRESH_MAX,
                    thresh_min_step: DEFAULT_THRESH_MIN_STEP,
                    // Oracle authority (disabled by default - use Pyth/Chainlink)
                    // In Hyperp mode: authority_price_e6 = mark, last_effective_price_e6 = index
                    oracle_authority: [0u8; 32],
                    authority_price_e6: if is_hyperp { initial_mark_price_e6 } else { 0 },
                    authority_timestamp: 0, // In Hyperp mode: stores funding rate (bps per slot)
                    // Oracle price circuit breaker
                    // In Hyperp mode: used for rate-limited index smoothing AND mark price clamping
                    // Default: disabled for non-Hyperp, 1% per slot for Hyperp
                    oracle_price_cap_e2bps: if is_hyperp {
                        DEFAULT_HYPERP_PRICE_CAP_E2BPS
                    } else {
                        0
                    },
                    last_effective_price_e6: if is_hyperp { initial_mark_price_e6 } else { 0 },
                };
                state::write_config(&mut data, &config);

                let new_header = SlabHeader {
                    magic: MAGIC,
                    version: VERSION,
                    bump,
                    _padding: [0; 3],
                    admin: a_admin.key.to_bytes(),
                    _reserved: [0; 24],
                };
                state::write_header(&mut data, &new_header);
                // Step 4: Explicitly initialize nonce to 0 for determinism
                state::write_req_nonce(&mut data, 0);
                // Initialize threshold update slot to 0
                state::write_last_thr_update_slot(&mut data, 0);
            }
            Instruction::InitUser { fee_payment } => {
                accounts::expect_len(accounts, 5)?;
                let a_user = &accounts[0];
                let a_slab = &accounts[1];
                let a_user_ata = &accounts[2];
                let a_vault = &accounts[3];
                let a_token = &accounts[4];

                accounts::expect_signer(a_user)?;
                accounts::expect_writable(a_slab)?;
                verify_token_program(a_token)?;

                let mut data = state::slab_data_mut(a_slab)?;
                slab_guard(program_id, a_slab, &data)?;
                require_initialized(&data)?;

                // Block new users when market is resolved
                if state::is_resolved(&data) {
                    return Err(ProgramError::InvalidAccountData);
                }
                let config = state::read_config(&data);
                let mint = Pubkey::new_from_array(config.collateral_mint);

                let (auth, _) = accounts::derive_vault_authority(program_id, a_slab.key);
                verify_vault(
                    a_vault,
                    &auth,
                    &mint,
                    &Pubkey::new_from_array(config.vault_pubkey),
                )?;
                verify_token_account(a_user_ata, a_user.key, &mint)?;

                // Transfer base tokens to vault
                collateral::deposit(a_token, a_user_ata, a_vault, a_user, fee_payment)?;

                // Convert base tokens to units for engine
                let (units, dust) = crate::units::base_to_units(fee_payment, config.unit_scale);

                // Accumulate dust
                let old_dust = state::read_dust_base(&data);
                state::write_dust_base(&mut data, old_dust.saturating_add(dust));

                let engine = zc::engine_mut(&mut data)?;
                let idx = engine.add_user(units as u128).map_err(map_risk_error)?;
                engine
                    .set_owner(idx, a_user.key.to_bytes())
                    .map_err(map_risk_error)?;
            }
            Instruction::InitLP {
                matcher_program,
                matcher_context,
                fee_payment,
            } => {
                accounts::expect_len(accounts, 5)?;
                let a_user = &accounts[0];
                let a_slab = &accounts[1];
                let a_user_ata = &accounts[2];
                let a_vault = &accounts[3];
                let a_token = &accounts[4];

                accounts::expect_signer(a_user)?;
                accounts::expect_writable(a_slab)?;
                verify_token_program(a_token)?;

                let mut data = state::slab_data_mut(a_slab)?;
                slab_guard(program_id, a_slab, &data)?;
                require_initialized(&data)?;

                // Block new LPs when market is resolved
                if state::is_resolved(&data) {
                    return Err(ProgramError::InvalidAccountData);
                }

                let config = state::read_config(&data);
                let mint = Pubkey::new_from_array(config.collateral_mint);

                let (auth, _) = accounts::derive_vault_authority(program_id, a_slab.key);
                verify_vault(
                    a_vault,
                    &auth,
                    &mint,
                    &Pubkey::new_from_array(config.vault_pubkey),
                )?;
                verify_token_account(a_user_ata, a_user.key, &mint)?;

                // Transfer base tokens to vault
                collateral::deposit(a_token, a_user_ata, a_vault, a_user, fee_payment)?;

                // Convert base tokens to units for engine
                let (units, dust) = crate::units::base_to_units(fee_payment, config.unit_scale);

                // Accumulate dust
                let old_dust = state::read_dust_base(&data);
                state::write_dust_base(&mut data, old_dust.saturating_add(dust));

                let engine = zc::engine_mut(&mut data)?;
                let idx = engine
                    .add_lp(
                        matcher_program.to_bytes(),
                        matcher_context.to_bytes(),
                        units as u128,
                    )
                    .map_err(map_risk_error)?;
                engine
                    .set_owner(idx, a_user.key.to_bytes())
                    .map_err(map_risk_error)?;
            }
            Instruction::DepositCollateral { user_idx, amount } => {
                accounts::expect_len(accounts, 6)?;
                let a_user = &accounts[0];
                let a_slab = &accounts[1];
                let a_user_ata = &accounts[2];
                let a_vault = &accounts[3];
                let a_token = &accounts[4];
                let a_clock = &accounts[5];

                accounts::expect_signer(a_user)?;
                accounts::expect_writable(a_slab)?;
                verify_token_program(a_token)?;

                let mut data = state::slab_data_mut(a_slab)?;
                slab_guard(program_id, a_slab, &data)?;
                require_initialized(&data)?;

                // Block deposits when market is resolved
                if state::is_resolved(&data) {
                    return Err(ProgramError::InvalidAccountData);
                }

                let config = state::read_config(&data);
                let mint = Pubkey::new_from_array(config.collateral_mint);

                let (auth, _) = accounts::derive_vault_authority(program_id, a_slab.key);
                verify_vault(
                    a_vault,
                    &auth,
                    &mint,
                    &Pubkey::new_from_array(config.vault_pubkey),
                )?;
                verify_token_account(a_user_ata, a_user.key, &mint)?;

                let clock = Clock::from_account_info(a_clock)?;

                // Transfer base tokens to vault
                collateral::deposit(a_token, a_user_ata, a_vault, a_user, amount)?;

                // Convert base tokens to units for engine
                let (units, dust) = crate::units::base_to_units(amount, config.unit_scale);

                // Accumulate dust
                let old_dust = state::read_dust_base(&data);
                state::write_dust_base(&mut data, old_dust.saturating_add(dust));

                let engine = zc::engine_mut(&mut data)?;

                check_idx(engine, user_idx)?;

                // Owner authorization via verify helper (Kani-provable)
                let owner = engine.accounts[user_idx as usize].owner;
                if !crate::verify::owner_ok(owner, a_user.key.to_bytes()) {
                    return Err(PercolatorError::EngineUnauthorized.into());
                }

                engine
                    .deposit(user_idx, units as u128, clock.slot)
                    .map_err(map_risk_error)?;
            }
            Instruction::WithdrawCollateral { user_idx, amount } => {
                accounts::expect_len(accounts, 8)?;
                let a_user = &accounts[0];
                let a_slab = &accounts[1];
                let a_vault = &accounts[2];
                let a_user_ata = &accounts[3];
                let a_vault_pda = &accounts[4];
                let a_token = &accounts[5];
                let a_clock = &accounts[6];
                let a_oracle_idx = &accounts[7];

                accounts::expect_signer(a_user)?;
                accounts::expect_writable(a_slab)?;
                verify_token_program(a_token)?;

                let mut data = state::slab_data_mut(a_slab)?;
                slab_guard(program_id, a_slab, &data)?;
                require_initialized(&data)?;
                let mut config = state::read_config(&data);
                let mint = Pubkey::new_from_array(config.collateral_mint);

                let (derived_pda, _) = accounts::derive_vault_authority(program_id, a_slab.key);
                accounts::expect_key(a_vault_pda, &derived_pda)?;

                verify_vault(
                    a_vault,
                    &derived_pda,
                    &mint,
                    &Pubkey::new_from_array(config.vault_pubkey),
                )?;
                verify_token_account(a_user_ata, a_user.key, &mint)?;

                let clock = Clock::from_account_info(a_clock)?;
                // Read oracle price: Hyperp mode uses index directly, otherwise circuit-breaker clamping
                let is_hyperp = oracle::is_hyperp_mode(&config);
                let price = if is_hyperp {
                    let idx = config.last_effective_price_e6;
                    if idx == 0 {
                        return Err(PercolatorError::OracleInvalid.into());
                    }
                    idx
                } else {
                    oracle::read_price_clamped(&mut config, a_oracle_idx, clock.unix_timestamp)?
                };
                state::write_config(&mut data, &config);

                let engine = zc::engine_mut(&mut data)?;

                check_idx(engine, user_idx)?;

                // Owner authorization via verify helper (Kani-provable)
                let owner = engine.accounts[user_idx as usize].owner;
                if !crate::verify::owner_ok(owner, a_user.key.to_bytes()) {
                    return Err(PercolatorError::EngineUnauthorized.into());
                }

                // Reject misaligned withdrawal amounts (cleaner UX than silent floor)
                if config.unit_scale != 0 && amount % config.unit_scale as u64 != 0 {
                    return Err(ProgramError::InvalidInstructionData);
                }

                // Convert requested base tokens to units
                let (units_requested, _) = crate::units::base_to_units(amount, config.unit_scale);

                engine
                    .withdraw(user_idx, units_requested as u128, clock.slot, price)
                    .map_err(map_risk_error)?;

                // Convert units back to base tokens for payout (checked to prevent silent overflow)
                let base_to_pay =
                    crate::units::units_to_base_checked(units_requested, config.unit_scale)
                        .ok_or(PercolatorError::EngineOverflow)?;

                let seed1: &[u8] = b"vault";
                let seed2: &[u8] = a_slab.key.as_ref();
                let bump_arr: [u8; 1] = [config.vault_authority_bump];
                let seed3: &[u8] = &bump_arr;
                let seeds: [&[u8]; 3] = [seed1, seed2, seed3];
                let signer_seeds: [&[&[u8]]; 1] = [&seeds];

                collateral::withdraw(
                    a_token,
                    a_vault,
                    a_user_ata,
                    a_vault_pda,
                    base_to_pay,
                    &signer_seeds,
                )?;
            }
            Instruction::KeeperCrank {
                caller_idx,
                allow_panic,
            } => {
                use crate::constants::CRANK_NO_CALLER;

                accounts::expect_len(accounts, 4)?;
                let a_caller = &accounts[0];
                let a_slab = &accounts[1];
                let a_clock = &accounts[2];
                let a_oracle = &accounts[3];

                // Permissionless mode: caller_idx == u16::MAX means anyone can crank
                let permissionless = caller_idx == CRANK_NO_CALLER;

                if !permissionless {
                    // Self-crank mode: require signer + owner authorization
                    accounts::expect_signer(a_caller)?;
                }
                accounts::expect_writable(a_slab)?;

                let mut data = state::slab_data_mut(a_slab)?;
                slab_guard(program_id, a_slab, &data)?;
                require_initialized(&data)?;

                // Check if market is resolved - if so, force-close positions instead of normal crank
                if state::is_resolved(&data) {
                    let config = state::read_config(&data);
                    let settlement_price = config.authority_price_e6;
                    if settlement_price == 0 {
                        return Err(ProgramError::InvalidAccountData);
                    }

                    let clock = Clock::from_account_info(a_clock)?;
                    let engine = zc::engine_mut(&mut data)?;

                    // Force-close positions in a paginated manner using crank_cursor
                    // Process up to 64 accounts per crank call (bounded compute)
                    const BATCH_SIZE: u16 = 64;
                    let start = engine.crank_cursor;
                    let end = core::cmp::min(start + BATCH_SIZE, crate::percolator::MAX_ACCOUNTS as u16);

                    for idx in start..end {
                        if engine.is_used(idx as usize) {
                            let acc = &engine.accounts[idx as usize];
                            let pos = acc.position_size.get();
                            if pos != 0 {
                                // Settle position at settlement price
                                // PnL = position * (settlement_price - entry_price) / 1e6
                                let entry = acc.entry_price as i128;
                                let settle = settlement_price as i128;
                                let pnl_delta = pos.saturating_mul(settle.saturating_sub(entry))
                                    / 1_000_000i128;

                                // Add to PnL using set_pnl() to maintain pnl_pos_tot aggregate
                                // SECURITY: Must use set_pnl() for correct haircut calculations
                                let old_pnl = acc.pnl.get();
                                let new_pnl = old_pnl.saturating_add(pnl_delta);
                                engine.set_pnl(idx as usize, new_pnl);

                                // Initialize warmup slope for positive PnL so users can
                                // close accounts via CloseAccount after warmup elapses.
                                // Without this, warmup_slope_per_step stays 0 and
                                // settle_warmup_to_capital converts nothing (Bug #11).
                                if new_pnl > 0 {
                                    let avail = (new_pnl as u128).saturating_sub(
                                        engine.accounts[idx as usize].reserved_pnl as u128,
                                    );
                                    let period = engine.params.warmup_period_slots as u128;
                                    let slope = if period > 0 {
                                        core::cmp::max(1u128, avail / period)
                                    } else {
                                        avail // instant warmup
                                    };
                                    engine.accounts[idx as usize].warmup_slope_per_step =
                                        crate::percolator::U128::new(slope);
                                    engine.accounts[idx as usize].warmup_started_at_slot =
                                        clock.slot;
                                }

                                // Clear position
                                engine.accounts[idx as usize].position_size =
                                    crate::percolator::I128::ZERO;
                                engine.accounts[idx as usize].entry_price = 0;
                            }
                        }
                    }

                    // Update crank cursor for next call
                    engine.crank_cursor = if end >= crate::percolator::MAX_ACCOUNTS as u16 {
                        0
                    } else {
                        end
                    };
                    engine.current_slot = clock.slot;

                    return Ok(());
                }

                let mut config = state::read_config(&data);
                let header = state::read_header(&data);
                // Read last threshold update slot BEFORE mutable engine borrow
                let last_thr_slot = state::read_last_thr_update_slot(&data);

                // SECURITY (C4): allow_panic triggers global settlement - admin only
                // This prevents griefing attacks where anyone triggers panic at worst moment
                if allow_panic != 0 {
                    accounts::expect_signer(a_caller)?;
                    if !crate::verify::admin_ok(header.admin, a_caller.key.to_bytes()) {
                        return Err(PercolatorError::EngineUnauthorized.into());
                    }
                }

                // Read dust before borrowing engine (for dust sweep later)
                let dust_before = state::read_dust_base(&data);
                let unit_scale = config.unit_scale;

                let clock = Clock::from_account_info(a_clock)?;

                // Hyperp mode: use get_engine_oracle_price_e6 for rate-limited index smoothing
                // Otherwise: use read_price_clamped as before
                let is_hyperp = oracle::is_hyperp_mode(&config);
                let engine_last_slot = {
                    let engine = zc::engine_ref(&data)?;
                    engine.current_slot
                };

                let price = if is_hyperp {
                    // Hyperp mode: update index toward mark with rate limiting
                    oracle::get_engine_oracle_price_e6(
                        engine_last_slot,
                        clock.slot,
                        clock.unix_timestamp,
                        &mut config,
                        a_oracle,
                    )?
                } else {
                    oracle::read_price_clamped(&mut config, a_oracle, clock.unix_timestamp)?
                };

                // Hyperp mode: compute and store funding rate BEFORE engine borrow
                // This avoids borrow conflicts with config read/write
                let hyperp_funding_rate = if is_hyperp {
                    // Read previous funding rate (piecewise-constant: use stored rate, then update)
                    // authority_timestamp is reinterpreted as i64 funding rate in Hyperp mode
                    // Legacy states may still contain unix timestamps in this slot; clamp to policy.
                    let prev_rate = config.authority_timestamp.clamp(
                        -config.funding_max_bps_per_slot,
                        config.funding_max_bps_per_slot,
                    );

                    // Compute new rate from premium
                    let mark_e6 = config.authority_price_e6;
                    let index_e6 = config.last_effective_price_e6;
                    let new_rate = oracle::compute_premium_funding_bps_per_slot(
                        mark_e6,
                        index_e6,
                        config.funding_horizon_slots,
                        config.funding_k_bps,
                        config.funding_max_premium_bps,
                        config.funding_max_bps_per_slot,
                    );

                    // Store new rate in config for next crank
                    config.authority_timestamp = new_rate;

                    Some(prev_rate) // Use PREVIOUS rate for this crank (piecewise-constant model)
                } else {
                    None
                };
                state::write_config(&mut data, &config);

                let engine = zc::engine_mut(&mut data)?;

                // Crank authorization:
                // - Permissionless mode (caller_idx == u16::MAX): anyone can crank
                // - Self-crank mode: caller_idx must be a valid, existing account owned by signer
                if !permissionless {
                    check_idx(engine, caller_idx)?;
                    let stored_owner = engine.accounts[caller_idx as usize].owner;
                    if !crate::verify::owner_ok(stored_owner, a_caller.key.to_bytes()) {
                        return Err(PercolatorError::EngineUnauthorized.into());
                    }
                }
                // Execute crank with effective_caller_idx for clarity
                // In permissionless mode, pass CRANK_NO_CALLER to engine (out-of-range = no caller settle)
                let effective_caller_idx = if permissionless {
                    CRANK_NO_CALLER
                } else {
                    caller_idx
                };

                // Compute funding rate:
                // - Hyperp mode: use pre-computed rate (avoids borrow conflict)
                // - Normal mode: inventory-based funding from LP net position
                let effective_funding_rate = if let Some(rate) = hyperp_funding_rate {
                    rate
                } else {
                    // Normal mode: inventory-based funding from LP net position
                    // Engine internally gates same-slot compounding via dt = now_slot - last_funding_slot,
                    // so passing the same rate multiple times in the same slot is harmless (dt=0 => no change).
                    let net_lp_pos = crate::compute_net_lp_pos(engine);
                    crate::compute_inventory_funding_bps_per_slot(
                        net_lp_pos,
                        price,
                        config.funding_horizon_slots,
                        config.funding_k_bps,
                        config.funding_inv_scale_notional_e6,
                        config.funding_max_premium_bps,
                        config.funding_max_bps_per_slot,
                    )
                };
                #[cfg(feature = "cu-audit")]
                {
                    msg!("CU_CHECKPOINT: keeper_crank_start");
                    sol_log_compute_units();
                }
                let _outcome = engine
                    .keeper_crank(
                        effective_caller_idx,
                        clock.slot,
                        price,
                        effective_funding_rate,
                        allow_panic != 0,
                    )
                    .map_err(map_risk_error)?;
                #[cfg(feature = "cu-audit")]
                {
                    msg!("CU_CHECKPOINT: keeper_crank_end");
                    sol_log_compute_units();
                }

                // Dust sweep: if accumulated dust >= unit_scale, sweep to insurance fund
                // Done before copying stats so insurance balance reflects the sweep
                let remaining_dust = if unit_scale > 0 {
                    let scale = unit_scale as u64;
                    if dust_before >= scale {
                        let units_to_sweep = dust_before / scale;
                        engine
                            .top_up_insurance_fund(units_to_sweep as u128)
                            .map_err(map_risk_error)?;
                        Some(dust_before % scale)
                    } else {
                        None
                    }
                } else {
                    None
                };

                // Copy stats before threshold update (avoid borrow conflict)
                let liqs = engine.lifetime_liquidations;
                let force = engine.lifetime_force_realize_closes;
                let ins_low = engine.insurance_fund.balance.get() as u64;

                // --- Threshold auto-update (rate-limited + EWMA smoothed + step-clamped)
                if clock.slot >= last_thr_slot.saturating_add(config.thresh_update_interval_slots) {
                    let risk_units = crate::compute_system_risk_units(engine);
                    // Convert risk_units (contracts) to notional using price
                    let risk_notional = risk_units.saturating_mul(price as u128) / 1_000_000;
                    // raw target: floor + risk_notional * thresh_risk_bps / 10000
                    let raw_target = config.thresh_floor.saturating_add(
                        risk_notional.saturating_mul(config.thresh_risk_bps as u128) / 10_000,
                    );
                    let clamped_target = raw_target.clamp(config.thresh_min, config.thresh_max);
                    let current = engine.risk_reduction_threshold();
                    // EWMA: new = alpha * target + (1 - alpha) * current
                    let alpha = config.thresh_alpha_bps as u128;
                    let smoothed = (alpha * clamped_target + (10_000 - alpha) * current) / 10_000;
                    // Step clamp: max step = thresh_step_bps / 10000 of current (but at least thresh_min_step)
                    // Bug #6 fix: When current == 0, allow stepping to clamped_target directly
                    // Otherwise threshold would only increase by thresh_min_step (=1) per update
                    let max_step = if current == 0 {
                        clamped_target // Allow full jump when starting from zero
                    } else {
                        (current * config.thresh_step_bps as u128 / 10_000)
                            .max(config.thresh_min_step)
                    };
                    let final_thresh = if smoothed > current {
                        current.saturating_add(max_step.min(smoothed - current))
                    } else {
                        current.saturating_sub(max_step.min(current - smoothed))
                    };
                    engine.set_risk_reduction_threshold(
                        final_thresh.clamp(config.thresh_min, config.thresh_max),
                    );
                    drop(engine);
                    state::write_last_thr_update_slot(&mut data, clock.slot);
                }

                // Write remaining dust if sweep occurred
                if let Some(dust) = remaining_dust {
                    state::write_dust_base(&mut data, dust);
                }

                // Debug: log lifetime counters (sol_log_64: tag, liqs, force, max_accounts, insurance)
                msg!("CRANK_STATS");
                sol_log_64(0xC8A4C, liqs, force, MAX_ACCOUNTS as u64, ins_low);
            }
            Instruction::TradeNoCpi {
                lp_idx,
                user_idx,
                size,
            } => {
                accounts::expect_len(accounts, 5)?;
                let a_user = &accounts[0];
                let a_lp = &accounts[1];
                let a_slab = &accounts[2];

                accounts::expect_signer(a_user)?;
                accounts::expect_signer(a_lp)?;
                accounts::expect_writable(a_slab)?;

                let mut data = state::slab_data_mut(a_slab)?;
                slab_guard(program_id, a_slab, &data)?;
                require_initialized(&data)?;

                // Block trading when market is resolved
                if state::is_resolved(&data) {
                    return Err(ProgramError::InvalidAccountData);
                }

                let mut config = state::read_config(&data);

                let clock = Clock::from_account_info(&accounts[3])?;
                let a_oracle = &accounts[4];

                // Hyperp mode: reject TradeNoCpi to prevent mark price manipulation
                // All trades must go through TradeCpi with a pinned matcher
                if oracle::is_hyperp_mode(&config) {
                    return Err(PercolatorError::HyperpTradeNoCpiDisabled.into());
                }

                // Read oracle price with circuit-breaker clamping
                let price =
                    oracle::read_price_clamped(&mut config, a_oracle, clock.unix_timestamp)?;
                state::write_config(&mut data, &config);

                let engine = zc::engine_mut(&mut data)?;

                check_idx(engine, lp_idx)?;
                check_idx(engine, user_idx)?;

                let u_owner = engine.accounts[user_idx as usize].owner;

                // Owner authorization via verify helper (Kani-provable)
                if !crate::verify::owner_ok(u_owner, a_user.key.to_bytes()) {
                    return Err(PercolatorError::EngineUnauthorized.into());
                }
                let l_owner = engine.accounts[lp_idx as usize].owner;
                if !crate::verify::owner_ok(l_owner, a_lp.key.to_bytes()) {
                    return Err(PercolatorError::EngineUnauthorized.into());
                }

                // Gate: if insurance_fund <= threshold, only allow risk-reducing trades
                // LP delta is -size (LP takes opposite side of user's trade)
                // O(1) check after single O(n) scan
                // Gate activation via verify helper (Kani-provable)
                let bal = engine.insurance_fund.balance.get();
                let thr = engine.risk_reduction_threshold();
                if crate::verify::gate_active(thr, bal) {
                    #[cfg(feature = "cu-audit")]
                    {
                        msg!("CU_CHECKPOINT: trade_nocpi_compute_start");
                        sol_log_compute_units();
                    }
                    let risk_state = crate::LpRiskState::compute(engine);
                    #[cfg(feature = "cu-audit")]
                    {
                        msg!("CU_CHECKPOINT: trade_nocpi_compute_end");
                        sol_log_compute_units();
                    }
                    let old_lp_pos = engine.accounts[lp_idx as usize].position_size.get();
                    if risk_state.would_increase_risk(old_lp_pos, -size) {
                        return Err(PercolatorError::EngineRiskReductionOnlyMode.into());
                    }
                }

                #[cfg(feature = "cu-audit")]
                {
                    msg!("CU_CHECKPOINT: trade_nocpi_execute_start");
                    sol_log_compute_units();
                }
                engine
                    .execute_trade(&NoOpMatcher, lp_idx, user_idx, clock.slot, price, size)
                    .map_err(map_risk_error)?;
                #[cfg(feature = "cu-audit")]
                {
                    msg!("CU_CHECKPOINT: trade_nocpi_execute_end");
                    sol_log_compute_units();
                }
            }
            Instruction::TradeCpi {
                lp_idx,
                user_idx,
                size,
            } => {
                // Phase 1: Updated account layout - lp_pda must be in accounts
                accounts::expect_len(accounts, 8)?;
                let a_user = &accounts[0];
                let a_lp_owner = &accounts[1];
                let a_slab = &accounts[2];
                let a_clock = &accounts[3];
                let a_oracle = &accounts[4];
                let a_matcher_prog = &accounts[5];
                let a_matcher_ctx = &accounts[6];
                let a_lp_pda = &accounts[7];

                accounts::expect_signer(a_user)?;
                // Note: a_lp_owner does NOT need to be a signer for TradeCpi.
                // LP owner delegated trade authorization to the matcher program.
                // The matcher CPI (via LP PDA invoke_signed) validates the trade.
                accounts::expect_writable(a_slab)?;
                accounts::expect_writable(a_matcher_ctx)?;

                // Matcher shape validation via verify helper (Kani-provable)
                let matcher_shape = crate::verify::MatcherAccountsShape {
                    prog_executable: a_matcher_prog.executable,
                    ctx_executable: a_matcher_ctx.executable,
                    ctx_owner_is_prog: a_matcher_ctx.owner == a_matcher_prog.key,
                    ctx_len_ok: crate::verify::ctx_len_sufficient(a_matcher_ctx.data_len()),
                };
                if !crate::verify::matcher_shape_ok(matcher_shape) {
                    return Err(ProgramError::InvalidAccountData);
                }

                // Phase 1: Validate lp_pda is the correct PDA, system-owned, empty data, 0 lamports
                let lp_bytes = lp_idx.to_le_bytes();
                let (expected_lp_pda, bump) = Pubkey::find_program_address(
                    &[b"lp", a_slab.key.as_ref(), &lp_bytes],
                    program_id,
                );
                // PDA key validation via verify helper (Kani-provable)
                if !crate::verify::pda_key_matches(
                    expected_lp_pda.to_bytes(),
                    a_lp_pda.key.to_bytes(),
                ) {
                    return Err(ProgramError::InvalidSeeds);
                }
                // LP PDA shape validation via verify helper (Kani-provable)
                let lp_pda_shape = crate::verify::LpPdaShape {
                    is_system_owned: a_lp_pda.owner == &crate::solana_program::system_program::ID,
                    data_len_zero: a_lp_pda.data_len() == 0,
                    lamports_zero: **a_lp_pda.lamports.borrow() == 0,
                };
                if !crate::verify::lp_pda_shape_ok(lp_pda_shape) {
                    return Err(ProgramError::InvalidAccountData);
                }

                // Phase 3 & 4: Read engine state, generate nonce, validate matcher identity
                // Note: Use immutable borrow for reading to avoid ExternalAccountDataModified
                // Nonce write is deferred until after execute_trade
                let (lp_account_id, mut config, req_id, lp_matcher_prog, lp_matcher_ctx) = {
                    let data = a_slab.try_borrow_data()?;
                    slab_guard(program_id, a_slab, &*data)?;
                    require_initialized(&*data)?;

                    // Block trading when market is resolved
                    if state::is_resolved(&*data) {
                        return Err(ProgramError::InvalidAccountData);
                    }

                    let config = state::read_config(&*data);

                    // Phase 3: Monotonic nonce for req_id (prevents replay attacks)
                    // Nonce advancement via verify helper (Kani-provable)
                    let nonce = state::read_req_nonce(&*data);
                    let req_id = crate::verify::nonce_on_success(nonce);

                    let engine = zc::engine_ref(&*data)?;

                    check_idx(engine, lp_idx)?;
                    check_idx(engine, user_idx)?;

                    // Owner authorization via verify helper (Kani-provable)
                    let u_owner = engine.accounts[user_idx as usize].owner;
                    if !crate::verify::owner_ok(u_owner, a_user.key.to_bytes()) {
                        return Err(PercolatorError::EngineUnauthorized.into());
                    }
                    let l_owner = engine.accounts[lp_idx as usize].owner;
                    if !crate::verify::owner_ok(l_owner, a_lp_owner.key.to_bytes()) {
                        return Err(PercolatorError::EngineUnauthorized.into());
                    }

                    let lp_acc = &engine.accounts[lp_idx as usize];
                    (
                        lp_acc.account_id,
                        config,
                        req_id,
                        lp_acc.matcher_program,
                        lp_acc.matcher_context,
                    )
                };

                // Matcher identity binding via verify helper (Kani-provable)
                if !crate::verify::matcher_identity_ok(
                    lp_matcher_prog,
                    lp_matcher_ctx,
                    a_matcher_prog.key.to_bytes(),
                    a_matcher_ctx.key.to_bytes(),
                ) {
                    return Err(PercolatorError::EngineInvalidMatchingEngine.into());
                }

                let clock = Clock::from_account_info(a_clock)?;
                // Read oracle price: Hyperp mode uses index directly, otherwise circuit-breaker clamping
                let is_hyperp = oracle::is_hyperp_mode(&config);
                let price = if is_hyperp {
                    // Hyperp mode: use current index price for trade execution
                    let idx = config.last_effective_price_e6;
                    if idx == 0 {
                        return Err(PercolatorError::OracleInvalid.into());
                    }
                    idx
                } else {
                    oracle::read_price_clamped(&mut config, a_oracle, clock.unix_timestamp)?
                };

                // Note: We don't zero the matcher_ctx before CPI because we don't own it.
                // Security is maintained by ABI validation which checks req_id (nonce),
                // lp_account_id, and oracle_price_e6 all match the request parameters.

                let mut cpi_data = alloc::vec::Vec::with_capacity(MATCHER_CALL_LEN);
                cpi_data.push(MATCHER_CALL_TAG);
                cpi_data.extend_from_slice(&req_id.to_le_bytes());
                cpi_data.extend_from_slice(&lp_idx.to_le_bytes());
                cpi_data.extend_from_slice(&lp_account_id.to_le_bytes());
                cpi_data.extend_from_slice(&price.to_le_bytes());
                cpi_data.extend_from_slice(&size.to_le_bytes());
                cpi_data.extend_from_slice(&[0u8; 24]); // padding to MATCHER_CALL_LEN

                #[cfg(debug_assertions)]
                {
                    if cpi_data.len() != MATCHER_CALL_LEN {
                        return Err(ProgramError::InvalidInstructionData);
                    }
                }

                let metas = alloc::vec![
                    AccountMeta::new_readonly(*a_lp_pda.key, true), // Will become signer via invoke_signed
                    AccountMeta::new(*a_matcher_ctx.key, false),
                ];

                let ix = SolInstruction {
                    program_id: *a_matcher_prog.key,
                    accounts: metas,
                    data: cpi_data,
                };

                let bump_arr = [bump];
                let seeds: &[&[u8]] = &[b"lp", a_slab.key.as_ref(), &lp_bytes, &bump_arr];

                // Phase 2: Use zc helper for CPI - slab not passed to avoid ExternalAccountDataModified
                zc::invoke_signed_trade(&ix, a_lp_pda, a_matcher_ctx, seeds)?;

                let ctx_data = a_matcher_ctx.try_borrow_data()?;
                let ret = crate::matcher_abi::read_matcher_return(&ctx_data)?;
                // ABI validation via verify helper (Kani-provable)
                let ret_fields = crate::verify::MatcherReturnFields {
                    abi_version: ret.abi_version,
                    flags: ret.flags,
                    exec_price_e6: ret.exec_price_e6,
                    exec_size: ret.exec_size,
                    req_id: ret.req_id,
                    lp_account_id: ret.lp_account_id,
                    oracle_price_e6: ret.oracle_price_e6,
                    reserved: ret.reserved,
                };
                if !crate::verify::abi_ok(ret_fields, lp_account_id, price, size, req_id) {
                    return Err(ProgramError::InvalidAccountData);
                }
                drop(ctx_data);

                let matcher = CpiMatcher {
                    exec_price: ret.exec_price_e6,
                    exec_size: ret.exec_size,
                };
                {
                    let mut data = state::slab_data_mut(a_slab)?;
                    state::write_config(&mut data, &config);
                    let engine = zc::engine_mut(&mut data)?;

                    // Gate: if insurance_fund <= threshold, only allow risk-reducing trades
                    // Use actual exec_size from matcher (LP delta is -exec_size)
                    // O(1) check after single O(n) scan
                    // Gate activation via verify helper (Kani-provable)
                    let bal = engine.insurance_fund.balance.get();
                    let thr = engine.risk_reduction_threshold();
                    if crate::verify::gate_active(thr, bal) {
                        #[cfg(feature = "cu-audit")]
                        {
                            msg!("CU_CHECKPOINT: trade_cpi_compute_start");
                            sol_log_compute_units();
                        }
                        let risk_state = crate::LpRiskState::compute(engine);
                        #[cfg(feature = "cu-audit")]
                        {
                            msg!("CU_CHECKPOINT: trade_cpi_compute_end");
                            sol_log_compute_units();
                        }
                        let old_lp_pos = engine.accounts[lp_idx as usize].position_size.get();
                        if risk_state.would_increase_risk(old_lp_pos, -ret.exec_size) {
                            return Err(PercolatorError::EngineRiskReductionOnlyMode.into());
                        }
                    }

                    // Trade size selection via verify helper (Kani-provable: uses exec_size, not requested_size)
                    let trade_size = crate::verify::cpi_trade_size(ret.exec_size, size);
                    #[cfg(feature = "cu-audit")]
                    {
                        msg!("CU_CHECKPOINT: trade_cpi_execute_start");
                        sol_log_compute_units();
                    }
                    engine
                        .execute_trade(&matcher, lp_idx, user_idx, clock.slot, price, trade_size)
                        .map_err(map_risk_error)?;
                    #[cfg(feature = "cu-audit")]
                    {
                        msg!("CU_CHECKPOINT: trade_cpi_execute_end");
                        sol_log_compute_units();
                    }
                    // Write nonce AFTER CPI and execute_trade to avoid ExternalAccountDataModified
                    state::write_req_nonce(&mut data, req_id);

                    // Hyperp mode: update mark price with execution price
                    // Apply circuit breaker to prevent extreme mark price manipulation
                    if is_hyperp {
                        let mut config = state::read_config(&data);
                        // Clamp exec_price against current index to prevent manipulation
                        // Uses same circuit breaker as PushOraclePrice for consistency
                        let clamped_mark = oracle::clamp_oracle_price(
                            config.last_effective_price_e6,
                            ret.exec_price_e6,
                            config.oracle_price_cap_e2bps,
                        );
                        config.authority_price_e6 = clamped_mark;
                        state::write_config(&mut data, &config);
                    }
                }
            }
            Instruction::LiquidateAtOracle { target_idx } => {
                accounts::expect_len(accounts, 4)?;
                let a_slab = &accounts[1];
                let a_oracle = &accounts[3];
                accounts::expect_writable(a_slab)?;

                let mut data = state::slab_data_mut(a_slab)?;
                slab_guard(program_id, a_slab, &data)?;
                require_initialized(&data)?;
                let mut config = state::read_config(&data);

                let clock = Clock::from_account_info(&accounts[2])?;
                // Read oracle price: Hyperp mode uses index directly, otherwise circuit-breaker clamping
                let is_hyperp = oracle::is_hyperp_mode(&config);
                let price = if is_hyperp {
                    let idx = config.last_effective_price_e6;
                    if idx == 0 {
                        return Err(PercolatorError::OracleInvalid.into());
                    }
                    idx
                } else {
                    oracle::read_price_clamped(&mut config, a_oracle, clock.unix_timestamp)?
                };
                state::write_config(&mut data, &config);

                let engine = zc::engine_mut(&mut data)?;

                check_idx(engine, target_idx)?;

                // Debug logging for liquidation (using sol_log_64 for no_std)
                sol_log_64(target_idx as u64, price, 0, 0, 0); // idx, price
                {
                    let acc = &engine.accounts[target_idx as usize];
                    sol_log_64(acc.capital.get() as u64, acc.pnl.get() as u64, 0, 0, 1); // cap, pnl
                    sol_log_64(acc.position_size.get() as u64, acc.entry_price, 0, 0, 2); // pos, entry
                                                                                          // Calculate mark PnL
                    let pos = acc.position_size.get();
                    let entry = acc.entry_price as i128;
                    let mark = pos.saturating_mul(price as i128 - entry) / 1_000_000;
                    let equity = (acc.capital.get() as i128)
                        .saturating_add(acc.pnl.get())
                        .saturating_add(mark);
                    let notional = (if pos < 0 { -pos } else { pos } as u128)
                        .saturating_mul(price as u128)
                        / 1_000_000;
                    let maint_req = notional
                        .saturating_mul(engine.params.maintenance_margin_bps as u128)
                        / 10_000;
                    sol_log_64(mark as u64, equity as u64, maint_req as u64, 0, 3);
                    // mark, equity, maint
                }

                #[cfg(feature = "cu-audit")]
                {
                    msg!("CU_CHECKPOINT: liquidate_start");
                    sol_log_compute_units();
                }
                let _res = engine
                    .liquidate_at_oracle(target_idx, clock.slot, price)
                    .map_err(map_risk_error)?;
                sol_log_64(_res as u64, 0, 0, 0, 4); // result
                #[cfg(feature = "cu-audit")]
                {
                    msg!("CU_CHECKPOINT: liquidate_end");
                    sol_log_compute_units();
                }
            }
            Instruction::CloseAccount { user_idx } => {
                accounts::expect_len(accounts, 8)?;
                let a_user = &accounts[0];
                let a_slab = &accounts[1];
                let a_vault = &accounts[2];
                let a_user_ata = &accounts[3];
                let a_pda = &accounts[4];
                let a_token = &accounts[5];
                let a_oracle = &accounts[7];

                accounts::expect_signer(a_user)?;
                accounts::expect_writable(a_slab)?;
                verify_token_program(a_token)?;

                let mut data = state::slab_data_mut(a_slab)?;
                slab_guard(program_id, a_slab, &data)?;
                require_initialized(&data)?;
                let mut config = state::read_config(&data);
                let mint = Pubkey::new_from_array(config.collateral_mint);

                let (auth, _) = accounts::derive_vault_authority(program_id, a_slab.key);
                verify_vault(
                    a_vault,
                    &auth,
                    &mint,
                    &Pubkey::new_from_array(config.vault_pubkey),
                )?;
                verify_token_account(a_user_ata, a_user.key, &mint)?;
                accounts::expect_key(a_pda, &auth)?;

                let clock = Clock::from_account_info(&accounts[6])?;
                // Read oracle price: Hyperp mode uses index directly, otherwise circuit-breaker clamping
                let is_hyperp = oracle::is_hyperp_mode(&config);
                let price = if is_hyperp {
                    let idx = config.last_effective_price_e6;
                    if idx == 0 {
                        return Err(PercolatorError::OracleInvalid.into());
                    }
                    idx
                } else {
                    oracle::read_price_clamped(&mut config, a_oracle, clock.unix_timestamp)?
                };
                state::write_config(&mut data, &config);

                let engine = zc::engine_mut(&mut data)?;

                check_idx(engine, user_idx)?;

                // Owner authorization via verify helper (Kani-provable)
                let u_owner = engine.accounts[user_idx as usize].owner;
                if !crate::verify::owner_ok(u_owner, a_user.key.to_bytes()) {
                    return Err(PercolatorError::EngineUnauthorized.into());
                }

                #[cfg(feature = "cu-audit")]
                {
                    msg!("CU_CHECKPOINT: close_account_start");
                    sol_log_compute_units();
                }
                let amt_units = engine
                    .close_account(user_idx, clock.slot, price)
                    .map_err(map_risk_error)?;
                #[cfg(feature = "cu-audit")]
                {
                    msg!("CU_CHECKPOINT: close_account_end");
                    sol_log_compute_units();
                }
                let amt_units_u64: u64 = amt_units
                    .try_into()
                    .map_err(|_| PercolatorError::EngineOverflow)?;

                // Convert units to base tokens for payout (checked to prevent silent overflow)
                let base_to_pay =
                    crate::units::units_to_base_checked(amt_units_u64, config.unit_scale)
                        .ok_or(PercolatorError::EngineOverflow)?;

                let seed1: &[u8] = b"vault";
                let seed2: &[u8] = a_slab.key.as_ref();
                let bump_arr: [u8; 1] = [config.vault_authority_bump];
                let seed3: &[u8] = &bump_arr;
                let seeds: [&[u8]; 3] = [seed1, seed2, seed3];
                let signer_seeds: [&[&[u8]]; 1] = [&seeds];

                collateral::withdraw(
                    a_token,
                    a_vault,
                    a_user_ata,
                    a_pda,
                    base_to_pay,
                    &signer_seeds,
                )?;
            }
            Instruction::TopUpInsurance { amount } => {
                accounts::expect_len(accounts, 5)?;
                let a_user = &accounts[0];
                let a_slab = &accounts[1];
                let a_user_ata = &accounts[2];
                let a_vault = &accounts[3];
                let a_token = &accounts[4];

                accounts::expect_signer(a_user)?;
                accounts::expect_writable(a_slab)?;
                verify_token_program(a_token)?;

                let mut data = state::slab_data_mut(a_slab)?;
                slab_guard(program_id, a_slab, &data)?;
                require_initialized(&data)?;

                // Block insurance top-up when market is resolved
                if state::is_resolved(&data) {
                    return Err(ProgramError::InvalidAccountData);
                }

                let config = state::read_config(&data);
                let mint = Pubkey::new_from_array(config.collateral_mint);

                let (auth, _) = accounts::derive_vault_authority(program_id, a_slab.key);
                verify_vault(
                    a_vault,
                    &auth,
                    &mint,
                    &Pubkey::new_from_array(config.vault_pubkey),
                )?;
                verify_token_account(a_user_ata, a_user.key, &mint)?;

                // Transfer base tokens to vault
                collateral::deposit(a_token, a_user_ata, a_vault, a_user, amount)?;

                // Convert base tokens to units for engine
                let (units, dust) = crate::units::base_to_units(amount, config.unit_scale);

                // Accumulate dust
                let old_dust = state::read_dust_base(&data);
                state::write_dust_base(&mut data, old_dust.saturating_add(dust));

                let engine = zc::engine_mut(&mut data)?;
                engine
                    .top_up_insurance_fund(units as u128)
                    .map_err(map_risk_error)?;
            }
            Instruction::SetRiskThreshold { new_threshold } => {
                accounts::expect_len(accounts, 2)?;
                let a_admin = &accounts[0];
                let a_slab = &accounts[1];

                accounts::expect_signer(a_admin)?;
                accounts::expect_writable(a_slab)?;

                let mut data = state::slab_data_mut(a_slab)?;
                slab_guard(program_id, a_slab, &data)?;
                require_initialized(&data)?;
                if state::is_resolved(&data) {
                    return Err(ProgramError::InvalidAccountData);
                }

                let header = state::read_header(&data);
                require_admin(header.admin, a_admin.key)?;

                let engine = zc::engine_mut(&mut data)?;
                engine.set_risk_reduction_threshold(new_threshold);
            }

            Instruction::UpdateAdmin { new_admin } => {
                accounts::expect_len(accounts, 2)?;
                let a_admin = &accounts[0];
                let a_slab = &accounts[1];

                accounts::expect_signer(a_admin)?;
                accounts::expect_writable(a_slab)?;

                let mut data = state::slab_data_mut(a_slab)?;
                slab_guard(program_id, a_slab, &data)?;
                require_initialized(&data)?;

                let mut header = state::read_header(&data);
                require_admin(header.admin, a_admin.key)?;

                header.admin = new_admin.to_bytes();
                state::write_header(&mut data, &header);
            }

            Instruction::CloseSlab => {
                accounts::expect_len(accounts, 2)?;
                let a_dest = &accounts[0];
                let a_slab = &accounts[1];

                accounts::expect_signer(a_dest)?;
                accounts::expect_writable(a_slab)?;

                // With unsafe_close: skip all validation and zeroing (CU limit)
                // Account will be garbage collected after lamports are drained
                #[cfg(not(feature = "unsafe_close"))]
                {
                    let mut data = state::slab_data_mut(a_slab)?;
                    slab_guard(program_id, a_slab, &data)?;
                    require_initialized(&data)?;

                    let header = state::read_header(&data);
                    require_admin(header.admin, a_dest.key)?;

                    let engine = zc::engine_ref(&data)?;
                    if !engine.vault.is_zero() {
                        return Err(PercolatorError::EngineInsufficientBalance.into());
                    }
                    if !engine.insurance_fund.balance.is_zero() {
                        return Err(PercolatorError::EngineInsufficientBalance.into());
                    }
                    if engine.num_used_accounts != 0 {
                        return Err(PercolatorError::EngineAccountNotFound.into());
                    }

                    // Bug #3 fix: Check dust_base to prevent closing with unaccounted funds
                    let dust_base = state::read_dust_base(&data);
                    if dust_base != 0 {
                        return Err(PercolatorError::EngineInsufficientBalance.into());
                    }

                    // Zero out the slab data to prevent reuse
                    for b in data.iter_mut() {
                        *b = 0;
                    }
                }

                // Transfer all lamports from slab to destination
                let slab_lamports = a_slab.lamports();
                **a_slab.lamports.borrow_mut() = 0;
                **a_dest.lamports.borrow_mut() = a_dest
                    .lamports()
                    .checked_add(slab_lamports)
                    .ok_or(PercolatorError::EngineOverflow)?;
            }

            Instruction::UpdateConfig {
                funding_horizon_slots,
                funding_k_bps,
                funding_inv_scale_notional_e6,
                funding_max_premium_bps,
                funding_max_bps_per_slot,
                thresh_floor,
                thresh_risk_bps,
                thresh_update_interval_slots,
                thresh_step_bps,
                thresh_alpha_bps,
                thresh_min,
                thresh_max,
                thresh_min_step,
            } => {
                accounts::expect_len(accounts, 2)?;
                let a_admin = &accounts[0];
                let a_slab = &accounts[1];

                accounts::expect_signer(a_admin)?;
                accounts::expect_writable(a_slab)?;

                let mut data = state::slab_data_mut(a_slab)?;
                slab_guard(program_id, a_slab, &data)?;
                require_initialized(&data)?;
                if state::is_resolved(&data) {
                    return Err(ProgramError::InvalidAccountData);
                }

                let header = state::read_header(&data);
                require_admin(header.admin, a_admin.key)?;

                // Validate parameters
                if funding_horizon_slots == 0 {
                    return Err(PercolatorError::InvalidConfigParam.into());
                }
                if funding_inv_scale_notional_e6 == 0 {
                    return Err(PercolatorError::InvalidConfigParam.into());
                }
                if thresh_alpha_bps > 10_000 {
                    return Err(PercolatorError::InvalidConfigParam.into());
                }
                if thresh_min > thresh_max {
                    return Err(PercolatorError::InvalidConfigParam.into());
                }

                // Read existing config and update
                let mut config = state::read_config(&data);
                config.funding_horizon_slots = funding_horizon_slots;
                config.funding_k_bps = funding_k_bps;
                config.funding_inv_scale_notional_e6 = funding_inv_scale_notional_e6;
                config.funding_max_premium_bps = funding_max_premium_bps;
                config.funding_max_bps_per_slot = funding_max_bps_per_slot;
                config.thresh_floor = thresh_floor;
                config.thresh_risk_bps = thresh_risk_bps;
                config.thresh_update_interval_slots = thresh_update_interval_slots;
                config.thresh_step_bps = thresh_step_bps;
                config.thresh_alpha_bps = thresh_alpha_bps;
                config.thresh_min = thresh_min;
                config.thresh_max = thresh_max;
                config.thresh_min_step = thresh_min_step;
                state::write_config(&mut data, &config);
            }

            Instruction::SetMaintenanceFee { new_fee } => {
                accounts::expect_len(accounts, 2)?;
                let a_admin = &accounts[0];
                let a_slab = &accounts[1];

                accounts::expect_signer(a_admin)?;
                accounts::expect_writable(a_slab)?;

                let mut data = state::slab_data_mut(a_slab)?;
                slab_guard(program_id, a_slab, &data)?;
                require_initialized(&data)?;
                if state::is_resolved(&data) {
                    return Err(ProgramError::InvalidAccountData);
                }

                let header = state::read_header(&data);
                require_admin(header.admin, a_admin.key)?;

                let engine = zc::engine_mut(&mut data)?;
                engine.params.maintenance_fee_per_slot = crate::percolator::U128::new(new_fee);
            }

            Instruction::SetOracleAuthority { new_authority } => {
                accounts::expect_len(accounts, 2)?;
                let a_admin = &accounts[0];
                let a_slab = &accounts[1];

                accounts::expect_signer(a_admin)?;
                accounts::expect_writable(a_slab)?;

                let mut data = state::slab_data_mut(a_slab)?;
                slab_guard(program_id, a_slab, &data)?;
                require_initialized(&data)?;
                if state::is_resolved(&data) {
                    return Err(ProgramError::InvalidAccountData);
                }

                let header = state::read_header(&data);
                require_admin(header.admin, a_admin.key)?;

                // Update oracle authority in config
                let mut config = state::read_config(&data);
                config.oracle_authority = new_authority.to_bytes();
                // Clear stored price when authority changes
                config.authority_price_e6 = 0;
                config.authority_timestamp = 0;
                state::write_config(&mut data, &config);
            }

            Instruction::PushOraclePrice {
                price_e6,
                timestamp,
            } => {
                accounts::expect_len(accounts, 2)?;
                let a_authority = &accounts[0];
                let a_slab = &accounts[1];

                accounts::expect_signer(a_authority)?;
                accounts::expect_writable(a_slab)?;

                let mut data = state::slab_data_mut(a_slab)?;
                slab_guard(program_id, a_slab, &data)?;
                require_initialized(&data)?;
                if state::is_resolved(&data) {
                    return Err(ProgramError::InvalidAccountData);
                }

                // Verify caller is the oracle authority
                let mut config = state::read_config(&data);
                let is_hyperp = oracle::is_hyperp_mode(&config);
                if config.oracle_authority == [0u8; 32] {
                    return Err(PercolatorError::EngineUnauthorized.into());
                }
                if config.oracle_authority != a_authority.key.to_bytes() {
                    return Err(PercolatorError::EngineUnauthorized.into());
                }

                // Validate price (must be positive)
                if price_e6 == 0 {
                    return Err(PercolatorError::OracleInvalid.into());
                }

                // For non-Hyperp markets, require monotonic authority timestamps.
                // This prevents stale rollback pushes from replacing fresher authority data.
                if !is_hyperp
                    && config.authority_timestamp != 0
                    && timestamp < config.authority_timestamp
                {
                    return Err(PercolatorError::OracleStale.into());
                }

                // Clamp the incoming price against circuit breaker
                let clamped = oracle::clamp_oracle_price(
                    config.last_effective_price_e6,
                    price_e6,
                    config.oracle_price_cap_e2bps,
                );
                config.authority_price_e6 = clamped;
                // In Hyperp mode this field stores previous funding-rate state (bps/slot),
                // not unix time. Keep it untouched so PushOraclePrice cannot clobber it.
                if !is_hyperp {
                    config.authority_timestamp = timestamp;
                }
                config.last_effective_price_e6 = clamped;
                state::write_config(&mut data, &config);
            }

            Instruction::SetOraclePriceCap { max_change_e2bps } => {
                accounts::expect_len(accounts, 2)?;
                let a_admin = &accounts[0];
                let a_slab = &accounts[1];

                accounts::expect_signer(a_admin)?;
                accounts::expect_writable(a_slab)?;

                let mut data = state::slab_data_mut(a_slab)?;
                slab_guard(program_id, a_slab, &data)?;
                require_initialized(&data)?;
                if state::is_resolved(&data) {
                    return Err(ProgramError::InvalidAccountData);
                }

                let header = state::read_header(&data);
                require_admin(header.admin, a_admin.key)?;

                let mut config = state::read_config(&data);
                config.oracle_price_cap_e2bps = max_change_e2bps;
                state::write_config(&mut data, &config);
            }

            Instruction::ResolveMarket => {
                // Resolve market: set RESOLVED flag, use admin oracle price for settlement
                // Positions are force-closed via subsequent KeeperCrank calls (paginated)
                accounts::expect_len(accounts, 2)?;
                let a_admin = &accounts[0];
                let a_slab = &accounts[1];

                accounts::expect_signer(a_admin)?;
                accounts::expect_writable(a_slab)?;

                let mut data = state::slab_data_mut(a_slab)?;
                slab_guard(program_id, a_slab, &data)?;
                require_initialized(&data)?;

                let header = state::read_header(&data);
                require_admin(header.admin, a_admin.key)?;

                // Can't re-resolve
                if state::is_resolved(&data) {
                    return Err(ProgramError::InvalidAccountData);
                }

                // Require admin oracle price to be set (authority_price_e6 > 0)
                let config = state::read_config(&data);
                if config.authority_price_e6 == 0 {
                    return Err(ProgramError::InvalidAccountData);
                }

                // Set the resolved flag
                state::set_resolved(&mut data);
            }

            Instruction::WithdrawInsurance => {
                // Withdraw insurance fund (admin only, requires RESOLVED and all positions closed)
                accounts::expect_len(accounts, 6)?;
                let a_admin = &accounts[0];
                let a_slab = &accounts[1];
                let a_admin_ata = &accounts[2];
                let a_vault = &accounts[3];
                let a_token = &accounts[4];
                let a_vault_pda = &accounts[5];

                accounts::expect_signer(a_admin)?;
                accounts::expect_writable(a_slab)?;
                verify_token_program(a_token)?;

                let mut data = state::slab_data_mut(a_slab)?;
                slab_guard(program_id, a_slab, &data)?;
                require_initialized(&data)?;

                let header = state::read_header(&data);
                require_admin(header.admin, a_admin.key)?;

                // Must be resolved
                if !state::is_resolved(&data) {
                    return Err(ProgramError::InvalidAccountData);
                }

                let config = state::read_config(&data);
                let mint = Pubkey::new_from_array(config.collateral_mint);

                let (auth, _) = accounts::derive_vault_authority(program_id, a_slab.key);
                verify_vault(
                    a_vault,
                    &auth,
                    &mint,
                    &Pubkey::new_from_array(config.vault_pubkey),
                )?;
                verify_token_account(a_admin_ata, a_admin.key, &mint)?;
                accounts::expect_key(a_vault_pda, &auth)?;

                let engine = zc::engine_mut(&mut data)?;

                // Require all positions to be closed (force-closed by crank)
                // Check that no account has position_size != 0
                let mut has_open_positions = false;
                for i in 0..crate::percolator::MAX_ACCOUNTS {
                    if engine.is_used(i) {
                        let pos = engine.accounts[i].position_size.get();
                        if pos != 0 {
                            has_open_positions = true;
                            break;
                        }
                    }
                }
                if has_open_positions {
                    return Err(ProgramError::InvalidAccountData);
                }

                // Get insurance balance and convert to base tokens
                let insurance_units = engine.insurance_fund.balance.get();
                if insurance_units == 0 {
                    return Ok(()); // Nothing to withdraw
                }

                // Cap at u64::MAX for conversion (should never happen in practice)
                let units_u64 = if insurance_units > u64::MAX as u128 {
                    u64::MAX
                } else {
                    insurance_units as u64
                };
                let base_amount = crate::units::units_to_base_checked(units_u64, config.unit_scale)
                    .ok_or(PercolatorError::EngineOverflow)?;

                // Zero out insurance fund
                engine.insurance_fund.balance = crate::percolator::U128::ZERO;

                // Transfer from vault to admin
                let seed1: &[u8] = b"vault";
                let seed2: &[u8] = a_slab.key.as_ref();
                let bump_arr: [u8; 1] = [config.vault_authority_bump];
                let seed3: &[u8] = &bump_arr;
                let seeds: [&[u8]; 3] = [seed1, seed2, seed3];
                let signer_seeds: [&[&[u8]]; 1] = [&seeds];

                collateral::withdraw(
                    a_token,
                    a_vault,
                    a_admin_ata,
                    a_vault_pda,
                    base_amount,
                    &signer_seeds,
                )?;
            }

            Instruction::AdminForceCloseAccount { user_idx } => {
                // Admin force-close an abandoned account after market resolution.
                // Settles PnL (with haircut for positive), forgives fee debt,
                // then delegates to engine.close_account() for the rest.
                accounts::expect_len(accounts, 8)?;
                let a_admin = &accounts[0];
                let a_slab = &accounts[1];
                let a_vault = &accounts[2];
                let a_owner_ata = &accounts[3];
                let a_pda = &accounts[4];
                let a_token = &accounts[5];
                let a_oracle = &accounts[7];

                accounts::expect_signer(a_admin)?;
                accounts::expect_writable(a_slab)?;
                verify_token_program(a_token)?;

                let mut data = state::slab_data_mut(a_slab)?;
                slab_guard(program_id, a_slab, &data)?;
                require_initialized(&data)?;

                let header = state::read_header(&data);
                require_admin(header.admin, a_admin.key)?;

                // Must be resolved
                if !state::is_resolved(&data) {
                    return Err(ProgramError::InvalidAccountData);
                }

                let mut config = state::read_config(&data);
                let mint = Pubkey::new_from_array(config.collateral_mint);

                let (auth, _) = accounts::derive_vault_authority(program_id, a_slab.key);
                verify_vault(
                    a_vault,
                    &auth,
                    &mint,
                    &Pubkey::new_from_array(config.vault_pubkey),
                )?;
                accounts::expect_key(a_pda, &auth)?;

                let clock = Clock::from_account_info(&accounts[6])?;

                // Read oracle price (hyperp uses last_effective_price_e6)
                let is_hyperp = oracle::is_hyperp_mode(&config);
                let price = if is_hyperp {
                    let idx = config.last_effective_price_e6;
                    if idx == 0 {
                        return Err(PercolatorError::OracleInvalid.into());
                    }
                    idx
                } else {
                    oracle::read_price_clamped(&mut config, a_oracle, clock.unix_timestamp)?
                };
                state::write_config(&mut data, &config);

                let engine = zc::engine_mut(&mut data)?;

                check_idx(engine, user_idx)?;

                // Position must be zero (force-closed by prior crank)
                if !engine.accounts[user_idx as usize].position_size.is_zero() {
                    return Err(PercolatorError::EngineUndercollateralized.into());
                }

                // Read account owner pubkey and verify owner ATA
                let owner_pubkey = Pubkey::new_from_array(engine.accounts[user_idx as usize].owner);
                verify_token_account(a_owner_ata, &owner_pubkey, &mint)?;

                // Force-settle PnL so close_account's pnl==0 check passes
                let pnl = engine.accounts[user_idx as usize].pnl.get();
                let capital = engine.accounts[user_idx as usize].capital.get();
                if pnl > 0 {
                    let haircutted = engine.effective_pos_pnl(pnl);
                    engine.set_capital(user_idx as usize, capital.saturating_add(haircutted));
                    engine.set_pnl(user_idx as usize, 0);
                } else if pnl < 0 {
                    let loss = (-pnl) as u128;
                    engine.set_capital(user_idx as usize, capital.saturating_sub(loss));
                    engine.set_pnl(user_idx as usize, 0);
                }

                // Forgive fee debt so close_account doesn't fail
                engine.accounts[user_idx as usize].fee_credits = crate::percolator::I128::ZERO;

                // close_account: touch_account_full, free_slot, vault decrement
                let amt_units = engine
                    .close_account(user_idx, clock.slot, price)
                    .map_err(map_risk_error)?;
                let amt_units_u64: u64 = amt_units
                    .try_into()
                    .map_err(|_| PercolatorError::EngineOverflow)?;

                let base_to_pay =
                    crate::units::units_to_base_checked(amt_units_u64, config.unit_scale)
                        .ok_or(PercolatorError::EngineOverflow)?;

                let seed1: &[u8] = b"vault";
                let seed2: &[u8] = a_slab.key.as_ref();
                let bump_arr: [u8; 1] = [config.vault_authority_bump];
                let seed3: &[u8] = &bump_arr;
                let seeds: [&[u8]; 3] = [seed1, seed2, seed3];
                let signer_seeds: [&[&[u8]]; 1] = [&seeds];

                collateral::withdraw(
                    a_token,
                    a_vault,
                    a_owner_ata,
                    a_pda,
                    base_to_pay,
                    &signer_seeds,
                )?;
            }
            Instruction::RegisterGhost { user_idx, ghost_key } => {
                accounts::expect_len(accounts, 2)?;
                let a_owner = &accounts[0];
                let a_slab = &accounts[1];

                accounts::expect_signer(a_owner)?;
                accounts::expect_writable(a_slab)?;

                let mut data = state::slab_data_mut(a_slab)?;
                slab_guard(program_id, a_slab, &data)?;
                require_initialized(&data)?;

                let engine = zc::engine_mut(&mut data)?;
                check_idx(engine, user_idx)?;

                // Only the owner can register a ghost key
                let owner = engine.accounts[user_idx as usize].owner;
                if !crate::verify::owner_ok(owner, a_owner.key.to_bytes()) {
                    return Err(PercolatorError::EngineUnauthorized.into());
                }

                // Repurpose matcher_program as ghost_authority for User accounts
                if engine.accounts[user_idx as usize].kind != crate::percolator::AccountKind::User {
                    return Err(PercolatorError::EngineAccountKindMismatch.into());
                }
                engine.accounts[user_idx as usize].matcher_program = ghost_key.to_bytes();
                msg!("GHOST_REGISTERED");
            }
            Instruction::TradeGhost { lp_idx, user_idx, size } => {
                // Accounts: [matcher_signer, slab, clock, oracle, instructions_sysvar]
                accounts::expect_len(accounts, 5)?;
                let a_matcher = &accounts[0];
                let a_slab = &accounts[1];
                let a_clock = &accounts[2];
                let a_oracle = &accounts[3];
                let a_ix_sysvar = &accounts[4];

                accounts::expect_signer(a_matcher)?;
                accounts::expect_writable(a_slab)?;

                // Verify instructions sysvar
                if *a_ix_sysvar.key != crate::solana_program::sysvar::instructions::ID {
                    return Err(ProgramError::InvalidAccountData);
                }

                let mut data = state::slab_data_mut(a_slab)?;
                slab_guard(program_id, a_slab, &data)?;
                require_initialized(&data)?;

                let mut config = state::read_config(&data);
                if state::is_resolved(&data) {
                    return Err(ProgramError::InvalidAccountData);
                }

                let clock = Clock::from_account_info(a_clock)?;
                let is_hyperp = oracle::is_hyperp_mode(&config);

                // Use current price (scaled)
                let price = if is_hyperp {
                    config.last_effective_price_e6
                } else {
                    oracle::read_price_clamped(&mut config, a_oracle, clock.unix_timestamp)?
                };

                // Load and verify ghost signature
                let (ghost_auth, nonce) = {
                    let engine = zc::engine_ref(&data)?;
                    check_idx(engine, user_idx)?;
                    check_idx(engine, lp_idx)?;
                    let user = &engine.accounts[user_idx as usize];
                    if user.kind != crate::percolator::AccountKind::User {
                        return Err(PercolatorError::EngineAccountKindMismatch.into());
                    }
                    let ghost_auth = user.matcher_program; // repurposed field
                    if ghost_auth == [0u8; 32] {
                        return Err(PercolatorError::GhostSignatureNotFound.into());
                    }
                    let nonce = u64::from_le_bytes(user.matcher_context[0..8].try_into().unwrap());
                    (ghost_auth, nonce)
                };

                // Message: [lp_idx(2), user_idx(2), size(16), nonce(8)] = 28 bytes
                let mut expected_msg = [0u8; 28];
                expected_msg[0..2].copy_from_slice(&lp_idx.to_le_bytes());
                expected_msg[2..4].copy_from_slice(&user_idx.to_le_bytes());
                expected_msg[4..20].copy_from_slice(&size.to_le_bytes());
                expected_msg[20..28].copy_from_slice(&nonce.to_le_bytes());

                // Introspect instructions to find Ed25519 signature verification
                // We assume it is the instruction immediately preceding this one (index - 1)
                let current_idx = crate::solana_program::sysvar::instructions::load_current_index(&a_ix_sysvar.try_borrow_data()?) as usize;
                if current_idx == 0 {
                    return Err(PercolatorError::GhostSignatureNotFound.into());
                }

                let prev_ix = crate::solana_program::sysvar::instructions::load_instruction_at_checked(
                    current_idx - 1,
                    &a_ix_sysvar
                )?;

                // Ed25519 Program ID
                if prev_ix.program_id != crate::solana_program::ed25519_program::ID {
                    return Err(PercolatorError::GhostSignatureNotFound.into());
                }

                /* Ed25519 instruction data layout:
                 * num_signatures: u8
                 * padding: u8
                 * signature_off: u16
                 * signature_instruction_index: u16
                 * public_key_off: u16
                 * public_key_instruction_index: u16
                 * message_off: u16
                 * message_size: u16
                 * message_instruction_index: u16
                 * ... signatures ...
                 * ... public keys ...
                 * ... messages ...
                 */
                if prev_ix.data.len() < 16 {
                    return Err(PercolatorError::GhostSignatureInvalid.into());
                }
                let num_sigs = prev_ix.data[0];
                if num_sigs == 0 {
                    return Err(PercolatorError::GhostSignatureInvalid.into());
                }

                let pubkey_off = u16::from_le_bytes(prev_ix.data[6..8].try_into().unwrap()) as usize;
                let pubkey_ix = u16::from_le_bytes(prev_ix.data[8..10].try_into().unwrap());
                let msg_off = u16::from_le_bytes(prev_ix.data[10..12].try_into().unwrap()) as usize;
                let msg_size = u16::from_le_bytes(prev_ix.data[12..14].try_into().unwrap()) as usize;
                let msg_ix = u16::from_le_bytes(prev_ix.data[14..16].try_into().unwrap());

                if pubkey_ix != 0xFFFF || msg_ix != 0xFFFF {
                    return Err(PercolatorError::GhostSignatureInvalid.into());
                }

                if prev_ix.data.len() < pubkey_off + 32 || prev_ix.data.len() < msg_off + msg_size {
                    return Err(PercolatorError::GhostSignatureInvalid.into());
                }

                let sig_pubkey = &prev_ix.data[pubkey_off..pubkey_off + 32];
                let sig_msg = &prev_ix.data[msg_off..msg_off + msg_size];

                if sig_pubkey != ghost_auth {
                    return Err(PercolatorError::GhostSignatureMismatch.into());
                }
                if sig_msg != expected_msg {
                    return Err(PercolatorError::GhostSignatureMismatch.into());
                }

                // All checks passed, execute trade
                let engine = zc::engine_mut(&mut data)?;
                
                // NoOpMatcher used here because the trade intent is validated by ghost signature
                engine.execute_trade(&NoOpMatcher, lp_idx, user_idx, clock.slot, price, size)
                    .map_err(map_risk_error)?;

                // Update user nonce in matcher_context
                let mut ctx = engine.accounts[user_idx as usize].matcher_context;
                ctx[0..8].copy_from_slice(&(nonce.wrapping_add(1)).to_le_bytes());
                engine.accounts[user_idx as usize].matcher_context = ctx;

                state::write_config(&mut data, &config);
                msg!("GHOST_TRADE_EXECUTED");
            }
        }
        Ok(())
    }
}

// 10. mod entrypoint
pub mod entrypoint {
    use crate::processor;
    #[allow(unused_imports)]
    use alloc::format; // Required by entrypoint! macro in SBF builds
    use crate::solana_program::{
        account_info::AccountInfo, entrypoint, entrypoint::ProgramResult, pubkey::Pubkey,
    };

    entrypoint!(process_instruction);

    fn process_instruction<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
        instruction_data: &[u8],
    ) -> ProgramResult {
        processor::process_instruction(program_id, accounts, instruction_data)
    }
}

pub mod percolator_core {
//! Formally Verified Risk Engine for Perpetual DEX
//!
//! ⚠️ EDUCATIONAL USE ONLY - NOT PRODUCTION READY ⚠️
//!
//! This is an experimental research project for educational purposes only.
//! DO NOT use with real funds. Not independently audited. Not production ready.
//!
//! This module implements a formally verified risk engine that guarantees:
//! 1. User funds are safe against oracle manipulation attacks (within time window T)
//! 2. PNL warmup prevents instant withdrawal of manipulated profits
//! 3. ADL haircuts apply to unwrapped PNL first, protecting user principal
//! 4. Conservation of funds across all operations
//! 5. User isolation - one user's actions don't affect others
//!
//! All data structures are laid out in a single contiguous memory chunk,
//! suitable for a single Solana account.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(kani)]
extern crate kani;

// ============================================================================
// Constants
// ============================================================================

// MAX_ACCOUNTS is feature-configured, not target-configured.
// This ensures x86 and SBF builds use the same sizes for a given feature set.
#[cfg(kani)]
pub const MAX_ACCOUNTS: usize = 4; // Small for fast formal verification (1 bitmap word, 4 bits)

#[cfg(all(feature = "test", not(kani)))]
pub const MAX_ACCOUNTS: usize = 64; // Small for tests

#[cfg(all(not(kani), not(feature = "test")))]
pub const MAX_ACCOUNTS: usize = 4096; // Production

// Derived constants - all use size_of, no hardcoded values
pub const BITMAP_WORDS: usize = (MAX_ACCOUNTS + 63) / 64;
pub const MAX_ROUNDING_SLACK: u128 = MAX_ACCOUNTS as u128;
/// Mask for wrapping indices (MAX_ACCOUNTS must be power of 2)
const ACCOUNT_IDX_MASK: usize = MAX_ACCOUNTS - 1;

/// Maximum number of dust accounts to close per crank call.
/// Limits compute usage while still making progress on cleanup.
pub const GC_CLOSE_BUDGET: u32 = 32;

/// Number of occupied accounts to process per crank call.
/// When the system has fewer than this many accounts, one crank covers everything.
pub const ACCOUNTS_PER_CRANK: u16 = 256;

/// Hard liquidation budget per crank call (caps total work)
/// Set to 120 to keep worst-case crank CU under ~50% of Solana limit
pub const LIQ_BUDGET_PER_CRANK: u16 = 120;

/// Max number of force-realize closes per crank call.
/// Hard CU bound in force-realize mode. Liquidations are skipped when active.
pub const FORCE_REALIZE_BUDGET_PER_CRANK: u16 = 32;

/// Maximum oracle price (prevents overflow in mark_pnl calculations)
/// 10^15 allows prices up to $1B with 6 decimal places
pub const MAX_ORACLE_PRICE: u64 = 1_000_000_000_000_000;

/// Maximum absolute position size (prevents overflow in mark_pnl calculations)
/// 10^20 allows positions up to 100 billion units
/// Combined with MAX_ORACLE_PRICE, guarantees mark_pnl multiply won't overflow i128
pub const MAX_POSITION_ABS: u128 = 100_000_000_000_000_000_000;

// ============================================================================
// BPF-Safe 128-bit Types (see src/i128.rs)
// ============================================================================
pub use i128::{I128, U128};

// ============================================================================
// Core Data Structures
// ============================================================================

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccountKind {
    User = 0,
    LP = 1,
}

/// Unified account - can be user or LP
///
/// LPs are distinguished by having kind = LP and matcher_program/context set.
/// Users have kind = User and matcher arrays zeroed.
///
/// This unification ensures LPs receive the same risk management protections as users:
/// - PNL warmup
/// - ADL (Auto-Deleveraging)
/// - Liquidations
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Account {
    /// Unique account ID (monotonically increasing, never recycled)
    /// Note: Field order matches on-chain slab layout (account_id at offset 0)
    pub account_id: u64,

    // ========================================
    // Capital & PNL (universal)
    // ========================================
    /// Deposited capital (user principal or LP capital)
    /// NEVER reduced by ADL/socialization (Invariant I1)
    pub capital: U128,

    /// Account kind (User or LP)
    /// Note: Field is at offset 24 in on-chain layout, after capital
    pub kind: AccountKind,

    /// Realized PNL from trading (can be positive or negative)
    pub pnl: I128,

    /// PNL reserved for pending withdrawals
    /// Note: u64 to match on-chain slab layout (8 bytes, not 16)
    pub reserved_pnl: u64,

    // ========================================
    // Warmup (embedded, no separate struct)
    // ========================================
    /// Slot when warmup started
    pub warmup_started_at_slot: u64,

    /// Linear vesting rate per slot
    pub warmup_slope_per_step: U128,

    // ========================================
    // Position (universal)
    // ========================================
    /// Current position size (+ long, - short)
    pub position_size: I128,

    /// Last oracle mark price at which this account's position was settled (variation margin).
    /// NOT an average trade entry price.
    pub entry_price: u64,

    // ========================================
    // Funding (universal)
    // ========================================
    /// Funding index snapshot (quote per base, 1e6 scale)
    pub funding_index: I128,

    // ========================================
    // LP-specific (only meaningful for LP kind)
    // ========================================
    /// Matching engine program ID (zero for user accounts)
    pub matcher_program: [u8; 32],

    /// Matching engine context account (zero for user accounts)
    pub matcher_context: [u8; 32],

    // ========================================
    // Owner & Maintenance Fees (wrapper-related)
    // ========================================
    /// Owner pubkey (32 bytes, signature checks done by wrapper)
    pub owner: [u8; 32],

    /// Fee credits in capital units (can go negative if fees owed)
    pub fee_credits: I128,

    /// Last slot when maintenance fees were settled for this account
    pub last_fee_slot: u64,

}

impl Account {
    /// Check if this account is an LP
    pub fn is_lp(&self) -> bool {
        matches!(self.kind, AccountKind::LP)
    }

    /// Check if this account is a regular user
    pub fn is_user(&self) -> bool {
        matches!(self.kind, AccountKind::User)
    }
}

/// Helper to create empty account
fn empty_account() -> Account {
    Account {
        account_id: 0,
        capital: U128::ZERO,
        kind: AccountKind::User,
        pnl: I128::ZERO,
        reserved_pnl: 0,
        warmup_started_at_slot: 0,
        warmup_slope_per_step: U128::ZERO,
        position_size: I128::ZERO,
        entry_price: 0,
        funding_index: I128::ZERO,
        matcher_program: [0; 32],
        matcher_context: [0; 32],
        owner: [0; 32],
        fee_credits: I128::ZERO,
        last_fee_slot: 0,
    }
}

/// Insurance fund state
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InsuranceFund {
    /// Insurance fund balance
    pub balance: U128,

    /// Accumulated fees from trades
    pub fee_revenue: U128,
}

/// Outcome from oracle_close_position_core helper
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClosedOutcome {
    /// Absolute position size that was closed
    pub abs_pos: u128,
    /// Mark PnL from closing at oracle price
    pub mark_pnl: i128,
    /// Capital before settlement
    pub cap_before: u128,
    /// Capital after settlement
    pub cap_after: u128,
    /// Whether a position was actually closed
    pub position_was_closed: bool,
}

/// Risk engine parameters
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RiskParams {
    /// Warmup period in slots (time T)
    pub warmup_period_slots: u64,

    /// Maintenance margin ratio in basis points (e.g., 500 = 5%)
    pub maintenance_margin_bps: u64,

    /// Initial margin ratio in basis points
    pub initial_margin_bps: u64,

    /// Trading fee in basis points
    pub trading_fee_bps: u64,

    /// Maximum number of accounts
    pub max_accounts: u64,

    /// Flat account creation fee (absolute amount in capital units)
    pub new_account_fee: U128,

    /// Insurance fund threshold for entering risk-reduction-only mode
    /// If insurance fund balance drops below this, risk-reduction mode activates
    pub risk_reduction_threshold: U128,

    // ========================================
    // Maintenance Fee Parameters
    // ========================================
    /// Maintenance fee per account per slot (in capital units)
    /// Engine is purely slot-native; any per-day conversion is wrapper/UI responsibility
    pub maintenance_fee_per_slot: U128,

    /// Maximum allowed staleness before crank is required (in slots)
    /// Set to u64::MAX to disable crank freshness check
    pub max_crank_staleness_slots: u64,

    /// Liquidation fee in basis points (e.g., 50 = 0.50%)
    /// Paid from liquidated account's capital into insurance fund
    pub liquidation_fee_bps: u64,

    /// Absolute cap on liquidation fee (in capital units)
    /// Prevents whales paying enormous fees
    pub liquidation_fee_cap: U128,

    // ========================================
    // Partial Liquidation Parameters
    // ========================================
    /// Buffer above maintenance margin (in basis points) to target after partial liquidation.
    /// E.g., if maintenance is 500 bps (5%) and buffer is 100 bps (1%), we target 6% margin.
    /// This prevents immediate re-liquidation from small price movements.
    pub liquidation_buffer_bps: u64,

    /// Minimum absolute position size after partial liquidation.
    /// If remaining position would be below this threshold, full liquidation occurs.
    /// Prevents dust positions that are uneconomical to maintain or re-liquidate.
    /// Denominated in base units (same scale as position_size.abs()).
    pub min_liquidation_abs: U128,
}

/// Main risk engine state - fixed slab with bitmap
#[repr(C)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RiskEngine {
    /// Total vault balance (all deposited funds)
    pub vault: U128,

    /// Insurance fund
    pub insurance_fund: InsuranceFund,

    /// Risk parameters
    pub params: RiskParams,

    /// Current slot (for warmup calculations)
    pub current_slot: u64,

    /// Global funding index (quote per 1 base, scaled by 1e6)
    pub funding_index_qpb_e6: I128,

    /// Last slot when funding was accrued
    pub last_funding_slot: u64,

    /// Funding rate (bps per slot) in effect starting at last_funding_slot.
    /// This is the rate used for the interval [last_funding_slot, next_accrual).
    /// Anti-retroactivity: state changes at slot t can only affect funding for slots >= t.
    pub funding_rate_bps_per_slot_last: i64,

    // ========================================
    // Keeper Crank Tracking
    // ========================================
    /// Last slot when keeper crank was executed
    pub last_crank_slot: u64,

    /// Maximum allowed staleness before crank is required (in slots)
    pub max_crank_staleness_slots: u64,

    // ========================================
    // Open Interest Tracking (O(1))
    // ========================================
    /// Total open interest = sum of abs(position_size) across all accounts
    /// This measures total risk exposure in the system.
    pub total_open_interest: U128,

    // ========================================
    // O(1) Aggregates (spec §2.2, §4)
    // ========================================
    /// Sum of all account capital: C_tot = Σ C_i
    /// Maintained incrementally via set_capital() helper.
    pub c_tot: U128,

    /// Sum of all positive PnL: PNL_pos_tot = Σ max(PNL_i, 0)
    /// Maintained incrementally via set_pnl() helper.
    pub pnl_pos_tot: U128,

    // ========================================
    // Crank Cursors (bounded scan support)
    // ========================================
    /// Cursor for liquidation scan (wraps around MAX_ACCOUNTS)
    pub liq_cursor: u16,

    /// Cursor for garbage collection scan (wraps around MAX_ACCOUNTS)
    pub gc_cursor: u16,

    /// Slot when the current full sweep started (step 0 was executed)
    pub last_full_sweep_start_slot: u64,

    /// Slot when the last full sweep completed
    pub last_full_sweep_completed_slot: u64,

    /// Cursor: index where the next crank will start scanning
    pub crank_cursor: u16,

    /// Index where the current sweep started (for completion detection)
    pub sweep_start_idx: u16,

    // ========================================
    // Lifetime Counters (telemetry)
    // ========================================
    /// Total number of liquidations performed (lifetime)
    pub lifetime_liquidations: u64,

    /// Total number of force-realize closes performed (lifetime)
    pub lifetime_force_realize_closes: u64,

    // ========================================
    // LP Aggregates (O(1) maintained for funding/threshold)
    // ========================================
    /// Net LP position: sum of position_size across all LP accounts
    /// Updated incrementally in execute_trade and close paths
    pub net_lp_pos: I128,

    /// Sum of abs(position_size) across all LP accounts
    /// Updated incrementally in execute_trade and close paths
    pub lp_sum_abs: U128,

    /// Max abs(position_size) across all LP accounts (monotone upper bound)
    /// Only increases; reset via bounded sweep at sweep completion
    pub lp_max_abs: U128,

    /// In-progress max abs for current sweep (reset at sweep start, committed at completion)
    pub lp_max_abs_sweep: U128,

    // ========================================
    // Slab Management
    // ========================================
    /// Occupancy bitmap (4096 bits = 64 u64 words)
    pub used: [u64; BITMAP_WORDS],

    /// Number of used accounts (O(1) counter, fixes H2: fee bypass TOCTOU)
    pub num_used_accounts: u16,

    /// Next account ID to assign (monotonically increasing, never recycled)
    pub next_account_id: u64,

    /// Freelist head (u16::MAX = none)
    pub free_head: u16,


    /// Freelist next pointers
    pub next_free: [u16; MAX_ACCOUNTS],

    /// Account slab (4096 accounts)
    pub accounts: [Account; MAX_ACCOUNTS],
}

// ============================================================================
// Error Types
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RiskError {
    /// Insufficient balance for operation
    InsufficientBalance,

    /// Account would become undercollateralized
    Undercollateralized,

    /// Unauthorized operation
    Unauthorized,

    /// Invalid matching engine
    InvalidMatchingEngine,

    /// PNL not yet warmed up
    PnlNotWarmedUp,

    /// Arithmetic overflow
    Overflow,

    /// Account not found
    AccountNotFound,

    /// Account is not an LP account
    NotAnLPAccount,

    /// Position size mismatch
    PositionSizeMismatch,

    /// Account kind mismatch
    AccountKindMismatch,
}

pub type Result<T> = core::result::Result<T, RiskError>;

/// Outcome of a keeper crank operation
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CrankOutcome {
    /// Whether the crank successfully advanced last_crank_slot
    pub advanced: bool,
    /// Slots forgiven for caller's maintenance (50% discount via time forgiveness)
    pub slots_forgiven: u64,
    /// Whether caller's maintenance fee settle succeeded (false if undercollateralized)
    pub caller_settle_ok: bool,
    /// Whether force-realize mode is active (insurance at/below threshold)
    pub force_realize_needed: bool,
    /// Whether panic_settle_all should be called (system in stress)
    pub panic_needed: bool,
    /// Number of accounts liquidated during this crank
    pub num_liquidations: u32,
    /// Number of liquidation errors (triggers risk_reduction_only)
    pub num_liq_errors: u16,
    /// Number of dust accounts garbage collected during this crank
    pub num_gc_closed: u32,
    /// Number of positions force-closed during this crank (when force_realize_needed)
    pub force_realize_closed: u16,
    /// Number of force-realize errors during this crank
    pub force_realize_errors: u16,
    /// Index where this crank stopped (next crank continues from here)
    pub last_cursor: u16,
    /// Whether this crank completed a full sweep of all accounts
    pub sweep_complete: bool,
}

// ============================================================================
// Math Helpers (Saturating Arithmetic for Safety)
// ============================================================================

#[inline]
fn add_u128(a: u128, b: u128) -> u128 {
    a.saturating_add(b)
}

#[inline]
fn sub_u128(a: u128, b: u128) -> u128 {
    a.saturating_sub(b)
}

#[inline]
fn mul_u128(a: u128, b: u128) -> u128 {
    a.saturating_mul(b)
}

#[inline]
fn div_u128(a: u128, b: u128) -> Result<u128> {
    if b == 0 {
        Err(RiskError::Overflow) // Division by zero
    } else {
        Ok(a / b)
    }
}

#[inline]
fn clamp_pos_i128(val: i128) -> u128 {
    if val > 0 {
        val as u128
    } else {
        0
    }
}

#[allow(dead_code)]
#[inline]
fn clamp_neg_i128(val: i128) -> u128 {
    if val < 0 {
        neg_i128_to_u128(val)
    } else {
        0
    }
}

/// Saturating absolute value for i128 (handles i128::MIN without overflow)
#[inline]
fn saturating_abs_i128(val: i128) -> i128 {
    if val == i128::MIN {
        i128::MAX
    } else {
        val.abs()
    }
}

/// Safely convert negative i128 to u128 (handles i128::MIN without overflow)
///
/// For i128::MIN, -i128::MIN would overflow because i128::MAX + 1 cannot be represented.
/// We handle this by returning (i128::MAX as u128) + 1 = 170141183460469231731687303715884105728.
#[inline]
fn neg_i128_to_u128(val: i128) -> u128 {
    debug_assert!(val < 0, "neg_i128_to_u128 called with non-negative value");
    if val == i128::MIN {
        (i128::MAX as u128) + 1
    } else {
        (-val) as u128
    }
}

/// Safely convert u128 to i128 with clamping (handles values > i128::MAX)
///
/// If x > i128::MAX, the cast would wrap to a negative value.
/// We clamp to i128::MAX instead to preserve correctness of margin checks.
#[inline]
fn u128_to_i128_clamped(x: u128) -> i128 {
    if x > i128::MAX as u128 {
        i128::MAX
    } else {
        x as i128
    }
}

// ============================================================================
// Matching Engine Trait
// ============================================================================

/// Result of a successful trade execution from the matching engine
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TradeExecution {
    /// Actual execution price (may differ from oracle/requested price)
    pub price: u64,
    /// Actual executed size (may be partial fill)
    pub size: i128,
}

/// Trait for pluggable matching engines
///
/// Implementers can provide custom order matching logic via CPI.
/// The matching engine is responsible for validating and executing trades
/// according to its own rules (CLOB, AMM, RFQ, etc).
pub trait MatchingEngine {
    /// Execute a trade between LP and user
    ///
    /// # Arguments
    /// * `lp_program` - The LP's matching engine program ID
    /// * `lp_context` - The LP's matching engine context account
    /// * `lp_account_id` - Unique ID of the LP account (never recycled)
    /// * `oracle_price` - Current oracle price for reference
    /// * `size` - Requested position size (positive = long, negative = short)
    ///
    /// # Returns
    /// * `Ok(TradeExecution)` with actual executed price and size
    /// * `Err(RiskError)` if the trade is rejected
    ///
    /// # Safety
    /// The matching engine MUST verify user authorization before approving trades.
    /// The risk engine will check solvency after the trade executes.
    fn execute_match(
        &self,
        lp_program: &[u8; 32],
        lp_context: &[u8; 32],
        lp_account_id: u64,
        oracle_price: u64,
        size: i128,
    ) -> Result<TradeExecution>;
}

/// No-op matching engine (for testing)
/// Returns the requested price and size as-is
pub struct NoOpMatcher;

impl MatchingEngine for NoOpMatcher {
    fn execute_match(
        &self,
        _lp_program: &[u8; 32],
        _lp_context: &[u8; 32],
        _lp_account_id: u64,
        oracle_price: u64,
        size: i128,
    ) -> Result<TradeExecution> {
        // Return requested price/size unchanged (no actual matching logic)
        Ok(TradeExecution {
            price: oracle_price,
            size,
        })
    }
}

// ============================================================================
// Core Implementation
// ============================================================================

impl RiskEngine {
    /// Create a new risk engine (stack-allocates the full struct - avoid in BPF!)
    ///
    /// WARNING: This allocates ~6MB on the stack at MAX_ACCOUNTS=4096.
    /// For Solana BPF programs, use `init_in_place` instead.
    pub fn new(params: RiskParams) -> Self {
        let mut engine = Self {
            vault: U128::ZERO,
            insurance_fund: InsuranceFund {
                balance: U128::ZERO,
                fee_revenue: U128::ZERO,
            },
            params,
            current_slot: 0,
            funding_index_qpb_e6: I128::ZERO,
            last_funding_slot: 0,
            funding_rate_bps_per_slot_last: 0,
            last_crank_slot: 0,
            max_crank_staleness_slots: params.max_crank_staleness_slots,
            total_open_interest: U128::ZERO,
            c_tot: U128::ZERO,
            pnl_pos_tot: U128::ZERO,
            liq_cursor: 0,
            gc_cursor: 0,
            last_full_sweep_start_slot: 0,
            last_full_sweep_completed_slot: 0,
            crank_cursor: 0,
            sweep_start_idx: 0,
            lifetime_liquidations: 0,
            lifetime_force_realize_closes: 0,
            net_lp_pos: I128::ZERO,
            lp_sum_abs: U128::ZERO,
            lp_max_abs: U128::ZERO,
            lp_max_abs_sweep: U128::ZERO,
            used: [0; BITMAP_WORDS],
            num_used_accounts: 0,
            next_account_id: 0,
            free_head: 0,
            next_free: [0; MAX_ACCOUNTS],
            accounts: [empty_account(); MAX_ACCOUNTS],
        };

        // Initialize freelist: 0 -> 1 -> 2 -> ... -> 4095 -> NONE
        for i in 0..MAX_ACCOUNTS - 1 {
            engine.next_free[i] = (i + 1) as u16;
        }
        engine.next_free[MAX_ACCOUNTS - 1] = u16::MAX; // Sentinel

        engine
    }

    /// Initialize a RiskEngine in place (zero-copy friendly).
    ///
    /// PREREQUISITE: The memory backing `self` MUST be zeroed before calling.
    /// This method only sets non-zero fields to avoid touching the entire ~6MB struct.
    ///
    /// This is the correct way to initialize RiskEngine in Solana BPF programs
    /// where stack space is limited to 4KB.
    pub fn init_in_place(&mut self, params: RiskParams) {
        // Set params (non-zero field)
        self.params = params;
        self.max_crank_staleness_slots = params.max_crank_staleness_slots;

        // Initialize freelist: 0 -> 1 -> 2 -> ... -> MAX_ACCOUNTS-1 -> NONE
        // All other fields are zero which is correct for:
        // - vault, insurance_fund, current_slot, funding_index, etc. = 0
        // - used bitmap = all zeros (no accounts in use)
        // - accounts = all zeros (equivalent to empty_account())
        // - free_head = 0 (first free slot is 0)
        for i in 0..MAX_ACCOUNTS - 1 {
            self.next_free[i] = (i + 1) as u16;
        }
        self.next_free[MAX_ACCOUNTS - 1] = u16::MAX; // Sentinel
    }

    // ========================================
    // Bitmap Helpers
    // ========================================

    pub fn is_used(&self, idx: usize) -> bool {
        if idx >= MAX_ACCOUNTS {
            return false;
        }
        let w = idx >> 6;
        let b = idx & 63;
        ((self.used[w] >> b) & 1) == 1
    }

    fn set_used(&mut self, idx: usize) {
        let w = idx >> 6;
        let b = idx & 63;
        self.used[w] |= 1u64 << b;
    }

    fn clear_used(&mut self, idx: usize) {
        let w = idx >> 6;
        let b = idx & 63;
        self.used[w] &= !(1u64 << b);
    }

    fn for_each_used_mut<F: FnMut(usize, &mut Account)>(&mut self, mut f: F) {
        for (block, word) in self.used.iter().copied().enumerate() {
            let mut w = word;
            while w != 0 {
                let bit = w.trailing_zeros() as usize;
                let idx = block * 64 + bit;
                w &= w - 1; // Clear lowest bit
                if idx >= MAX_ACCOUNTS {
                    continue; // Guard against stray high bits in bitmap
                }
                f(idx, &mut self.accounts[idx]);
            }
        }
    }

    fn for_each_used<F: FnMut(usize, &Account)>(&self, mut f: F) {
        for (block, word) in self.used.iter().copied().enumerate() {
            let mut w = word;
            while w != 0 {
                let bit = w.trailing_zeros() as usize;
                let idx = block * 64 + bit;
                w &= w - 1; // Clear lowest bit
                if idx >= MAX_ACCOUNTS {
                    continue; // Guard against stray high bits in bitmap
                }
                f(idx, &self.accounts[idx]);
            }
        }
    }

    // ========================================
    // O(1) Aggregate Helpers (spec §4)
    // ========================================

    /// Mandatory helper: set account PnL and maintain pnl_pos_tot aggregate (spec §4.2).
    /// All code paths that modify PnL MUST call this.
    #[inline]
    pub fn set_pnl(&mut self, idx: usize, new_pnl: i128) {
        let old = self.accounts[idx].pnl.get();
        let old_pos = if old > 0 { old as u128 } else { 0 };
        let new_pos = if new_pnl > 0 { new_pnl as u128 } else { 0 };
        self.pnl_pos_tot = U128::new(
            self.pnl_pos_tot
                .get()
                .saturating_add(new_pos)
                .saturating_sub(old_pos),
        );
        self.accounts[idx].pnl = I128::new(new_pnl);
    }

    /// Helper: set account capital and maintain c_tot aggregate (spec §4.1).
    #[inline]
    pub fn set_capital(&mut self, idx: usize, new_capital: u128) {
        let old = self.accounts[idx].capital.get();
        if new_capital >= old {
            self.c_tot = U128::new(self.c_tot.get().saturating_add(new_capital - old));
        } else {
            self.c_tot = U128::new(self.c_tot.get().saturating_sub(old - new_capital));
        }
        self.accounts[idx].capital = U128::new(new_capital);
    }

    /// Recompute c_tot and pnl_pos_tot from account data. For test use after direct state mutation.
    pub fn recompute_aggregates(&mut self) {
        let mut c_tot = 0u128;
        let mut pnl_pos_tot = 0u128;
        self.for_each_used(|_idx, account| {
            c_tot = c_tot.saturating_add(account.capital.get());
            let pnl = account.pnl.get();
            if pnl > 0 {
                pnl_pos_tot = pnl_pos_tot.saturating_add(pnl as u128);
            }
        });
        self.c_tot = U128::new(c_tot);
        self.pnl_pos_tot = U128::new(pnl_pos_tot);
    }

    /// Compute haircut ratio (h_num, h_den) per spec §3.2.
    /// h = min(Residual, PNL_pos_tot) / PNL_pos_tot where Residual = max(0, V - C_tot - I).
    /// Returns (1, 1) when PNL_pos_tot == 0.
    #[inline]
    pub fn haircut_ratio(&self) -> (u128, u128) {
        let pnl_pos_tot = self.pnl_pos_tot.get();
        if pnl_pos_tot == 0 {
            return (1, 1);
        }
        let residual = self
            .vault
            .get()
            .saturating_sub(self.c_tot.get())
            .saturating_sub(self.insurance_fund.balance.get());
        let h_num = core::cmp::min(residual, pnl_pos_tot);
        (h_num, pnl_pos_tot)
    }

    /// Compute effective positive PnL after haircut for a given account PnL (spec §3.3).
    /// PNL_eff_pos_i = floor(max(PNL_i, 0) * h_num / h_den)
    #[inline]
    pub fn effective_pos_pnl(&self, pnl: i128) -> u128 {
        if pnl <= 0 {
            return 0;
        }
        let pos_pnl = pnl as u128;
        let (h_num, h_den) = self.haircut_ratio();
        if h_den == 0 {
            return pos_pnl;
        }
        // floor(pos_pnl * h_num / h_den)
        mul_u128(pos_pnl, h_num) / h_den
    }

    /// Compute effective realized equity per spec §3.3.
    /// Eq_real_i = max(0, C_i + min(PNL_i, 0) + PNL_eff_pos_i)
    #[inline]
    pub fn effective_equity(&self, account: &Account) -> u128 {
        let cap_i = u128_to_i128_clamped(account.capital.get());
        let neg_pnl = core::cmp::min(account.pnl.get(), 0);
        let eff_pos = self.effective_pos_pnl(account.pnl.get());
        let eq_i = cap_i
            .saturating_add(neg_pnl)
            .saturating_add(u128_to_i128_clamped(eff_pos));
        if eq_i > 0 {
            eq_i as u128
        } else {
            0
        }
    }

    // ========================================
    // Account Allocation
    // ========================================

    fn alloc_slot(&mut self) -> Result<u16> {
        if self.free_head == u16::MAX {
            return Err(RiskError::Overflow); // Slab full
        }
        let idx = self.free_head;
        self.free_head = self.next_free[idx as usize];
        self.set_used(idx as usize);
        // Increment O(1) counter atomically (fixes H2: TOCTOU fee bypass)
        self.num_used_accounts = self.num_used_accounts.saturating_add(1);
        Ok(idx)
    }

    /// Count used accounts
    fn count_used(&self) -> u64 {
        let mut count = 0u64;
        self.for_each_used(|_, _| {
            count += 1;
        });
        count
    }

    // ========================================
    // Account Management
    // ========================================

    /// Add a new user account
    pub fn add_user(&mut self, fee_payment: u128) -> Result<u16> {
        // Use O(1) counter instead of O(N) count_used() (fixes H2: TOCTOU fee bypass)
        let used_count = self.num_used_accounts as u64;
        if used_count >= self.params.max_accounts {
            return Err(RiskError::Overflow);
        }

        // Flat fee (no scaling)
        let required_fee = self.params.new_account_fee.get();
        if fee_payment < required_fee {
            return Err(RiskError::InsufficientBalance);
        }

        // Bug #4 fix: Compute excess payment to credit to user capital
        let excess = fee_payment.saturating_sub(required_fee);

        // Pay fee to insurance (fee tokens are deposited into vault)
        // Account for FULL fee_payment in vault, not just required_fee
        self.vault = self.vault + fee_payment;
        self.insurance_fund.balance = self.insurance_fund.balance + required_fee;
        self.insurance_fund.fee_revenue = self.insurance_fund.fee_revenue + required_fee;

        // Allocate slot and assign unique ID
        let idx = self.alloc_slot()?;
        let account_id = self.next_account_id;
        self.next_account_id = self.next_account_id.saturating_add(1);

        // Initialize account with excess credited to capital
        self.accounts[idx as usize] = Account {
            kind: AccountKind::User,
            account_id,
            capital: U128::new(excess), // Bug #4 fix: excess goes to user capital
            pnl: I128::ZERO,
            reserved_pnl: 0,
            warmup_started_at_slot: self.current_slot,
            warmup_slope_per_step: U128::ZERO,
            position_size: I128::ZERO,
            entry_price: 0,
            funding_index: self.funding_index_qpb_e6,
            matcher_program: [0; 32],
            matcher_context: [0; 32],
            owner: [0; 32],
            fee_credits: I128::ZERO,
            last_fee_slot: self.current_slot,
        };

        // Maintain c_tot aggregate (account was created with capital = excess)
        if excess > 0 {
            self.c_tot = U128::new(self.c_tot.get().saturating_add(excess));
        }

        Ok(idx)
    }

    /// Add a new LP account
    pub fn add_lp(
        &mut self,
        matching_engine_program: [u8; 32],
        matching_engine_context: [u8; 32],
        fee_payment: u128,
    ) -> Result<u16> {
        // Use O(1) counter instead of O(N) count_used() (fixes H2: TOCTOU fee bypass)
        let used_count = self.num_used_accounts as u64;
        if used_count >= self.params.max_accounts {
            return Err(RiskError::Overflow);
        }

        // Flat fee (no scaling)
        let required_fee = self.params.new_account_fee.get();
        if fee_payment < required_fee {
            return Err(RiskError::InsufficientBalance);
        }

        // Bug #4 fix: Compute excess payment to credit to LP capital
        let excess = fee_payment.saturating_sub(required_fee);

        // Pay fee to insurance (fee tokens are deposited into vault)
        // Account for FULL fee_payment in vault, not just required_fee
        self.vault = self.vault + fee_payment;
        self.insurance_fund.balance = self.insurance_fund.balance + required_fee;
        self.insurance_fund.fee_revenue = self.insurance_fund.fee_revenue + required_fee;

        // Allocate slot and assign unique ID
        let idx = self.alloc_slot()?;
        let account_id = self.next_account_id;
        self.next_account_id = self.next_account_id.saturating_add(1);

        // Initialize account with excess credited to capital
        self.accounts[idx as usize] = Account {
            kind: AccountKind::LP,
            account_id,
            capital: U128::new(excess), // Bug #4 fix: excess goes to LP capital
            pnl: I128::ZERO,
            reserved_pnl: 0,
            warmup_started_at_slot: self.current_slot,
            warmup_slope_per_step: U128::ZERO,
            position_size: I128::ZERO,
            entry_price: 0,
            funding_index: self.funding_index_qpb_e6,
            matcher_program: matching_engine_program,
            matcher_context: matching_engine_context,
            owner: [0; 32],
            fee_credits: I128::ZERO,
            last_fee_slot: self.current_slot,
        };

        // Maintain c_tot aggregate (account was created with capital = excess)
        if excess > 0 {
            self.c_tot = U128::new(self.c_tot.get().saturating_add(excess));
        }

        Ok(idx)
    }

    // ========================================
    // Maintenance Fees
    // ========================================

    /// Settle maintenance fees for an account.
    ///
    /// Returns the fee amount due (for keeper rebate calculation).
    ///
    /// Algorithm:
    /// 1. Compute dt = now_slot - account.last_fee_slot
    /// 2. If dt == 0, return 0 (no-op)
    /// 3. Compute due = fee_per_slot * dt
    /// 4. Deduct from fee_credits; if negative, pay from capital to insurance
    /// 5. If position exists and below maintenance after fee, return Err
    pub fn settle_maintenance_fee(
        &mut self,
        idx: u16,
        now_slot: u64,
        oracle_price: u64,
    ) -> Result<u128> {
        if idx as usize >= MAX_ACCOUNTS || !self.is_used(idx as usize) {
            return Err(RiskError::Unauthorized);
        }

        // Calculate elapsed time
        let dt = now_slot.saturating_sub(self.accounts[idx as usize].last_fee_slot);
        if dt == 0 {
            return Ok(0);
        }

        // Calculate fee due (engine is purely slot-native)
        let due = self
            .params
            .maintenance_fee_per_slot
            .get()
            .saturating_mul(dt as u128);

        // Update last_fee_slot
        self.accounts[idx as usize].last_fee_slot = now_slot;

        // Deduct from fee_credits (coupon: no insurance booking here —
        // insurance was already paid when credits were granted)
        self.accounts[idx as usize].fee_credits =
            self.accounts[idx as usize].fee_credits.saturating_sub(due as i128);

        // If fee_credits is negative, pay from capital using set_capital helper (spec §4.1)
        let mut paid_from_capital = 0u128;
        if self.accounts[idx as usize].fee_credits.is_negative() {
            let owed = neg_i128_to_u128(self.accounts[idx as usize].fee_credits.get());
            let current_cap = self.accounts[idx as usize].capital.get();
            let pay = core::cmp::min(owed, current_cap);

            // Use set_capital helper to maintain c_tot aggregate (spec §4.1)
            self.set_capital(idx as usize, current_cap.saturating_sub(pay));
            self.insurance_fund.balance = self.insurance_fund.balance + pay;
            self.insurance_fund.fee_revenue = self.insurance_fund.fee_revenue + pay;

            // Credit back what was paid
            self.accounts[idx as usize].fee_credits =
                self.accounts[idx as usize].fee_credits.saturating_add(pay as i128);
            paid_from_capital = pay;
        }

        // Check maintenance margin if account has a position (MTM check)
        if !self.accounts[idx as usize].position_size.is_zero() {
            let account_ref = &self.accounts[idx as usize];
            if !self.is_above_maintenance_margin_mtm(account_ref, oracle_price) {
                return Err(RiskError::Undercollateralized);
            }
        }

        Ok(paid_from_capital) // Return actual amount paid into insurance
    }

    /// Best-effort maintenance settle for crank paths.
    /// - Always advances last_fee_slot
    /// - Charges fees into insurance if possible
    /// - NEVER fails due to margin checks
    /// - Still returns Unauthorized if idx invalid
    fn settle_maintenance_fee_best_effort_for_crank(
        &mut self,
        idx: u16,
        now_slot: u64,
    ) -> Result<u128> {
        if idx as usize >= MAX_ACCOUNTS || !self.is_used(idx as usize) {
            return Err(RiskError::Unauthorized);
        }

        let dt = now_slot.saturating_sub(self.accounts[idx as usize].last_fee_slot);
        if dt == 0 {
            return Ok(0);
        }

        let due = self
            .params
            .maintenance_fee_per_slot
            .get()
            .saturating_mul(dt as u128);

        // Advance slot marker regardless
        self.accounts[idx as usize].last_fee_slot = now_slot;

        // Deduct from fee_credits (coupon: no insurance booking here —
        // insurance was already paid when credits were granted)
        self.accounts[idx as usize].fee_credits =
            self.accounts[idx as usize].fee_credits.saturating_sub(due as i128);

        // If negative, pay what we can from capital using set_capital helper (spec §4.1)
        let mut paid_from_capital = 0u128;
        if self.accounts[idx as usize].fee_credits.is_negative() {
            let owed = neg_i128_to_u128(self.accounts[idx as usize].fee_credits.get());
            let current_cap = self.accounts[idx as usize].capital.get();
            let pay = core::cmp::min(owed, current_cap);

            // Use set_capital helper to maintain c_tot aggregate (spec §4.1)
            self.set_capital(idx as usize, current_cap.saturating_sub(pay));
            self.insurance_fund.balance = self.insurance_fund.balance + pay;
            self.insurance_fund.fee_revenue = self.insurance_fund.fee_revenue + pay;

            self.accounts[idx as usize].fee_credits =
                self.accounts[idx as usize].fee_credits.saturating_add(pay as i128);
            paid_from_capital = pay;
        }

        Ok(paid_from_capital) // Return actual amount paid into insurance
    }

    /// Best-effort warmup settlement for crank: settles any warmed positive PnL to capital.
    /// Silently ignores errors (e.g., account not found) since crank must not stall on
    /// individual account issues. Used to drain abandoned accounts' positive PnL over time.
    fn settle_warmup_to_capital_for_crank(&mut self, idx: u16) {
        // Ignore errors: crank is best-effort and must continue processing other accounts
        let _ = self.settle_warmup_to_capital(idx);
    }

    /// Pay down existing fee debt (negative fee_credits) using available capital.
    /// Does not advance last_fee_slot or charge new fees — just sweeps capital
    /// that became available (e.g. after warmup settlement) into insurance.
    /// Uses set_capital helper to maintain c_tot aggregate (spec §4.1).
    fn pay_fee_debt_from_capital(&mut self, idx: u16) {
        if self.accounts[idx as usize].fee_credits.is_negative()
            && !self.accounts[idx as usize].capital.is_zero()
        {
            let owed = neg_i128_to_u128(self.accounts[idx as usize].fee_credits.get());
            let current_cap = self.accounts[idx as usize].capital.get();
            let pay = core::cmp::min(owed, current_cap);
            if pay > 0 {
                // Use set_capital helper to maintain c_tot aggregate (spec §4.1)
                self.set_capital(idx as usize, current_cap.saturating_sub(pay));
                self.insurance_fund.balance = self.insurance_fund.balance + pay;
                self.insurance_fund.fee_revenue = self.insurance_fund.fee_revenue + pay;
                self.accounts[idx as usize].fee_credits =
                    self.accounts[idx as usize].fee_credits.saturating_add(pay as i128);
            }
        }
    }

    /// Touch account for force-realize paths: settles funding, mark, and fees but
    /// uses best-effort fee settle that can't stall on margin checks.
    fn touch_account_for_force_realize(
        &mut self,
        idx: u16,
        now_slot: u64,
        oracle_price: u64,
    ) -> Result<()> {
        // Funding settle is required for correct pnl
        self.touch_account(idx)?;
        // Mark-to-market settlement (variation margin)
        self.settle_mark_to_oracle(idx, oracle_price)?;
        // Best-effort fees; never fails due to maintenance margin
        let _ = self.settle_maintenance_fee_best_effort_for_crank(idx, now_slot)?;
        Ok(())
    }

    /// Touch account for liquidation paths: settles funding, mark, and fees but
    /// uses best-effort fee settle since we're about to liquidate anyway.
    fn touch_account_for_liquidation(
        &mut self,
        idx: u16,
        now_slot: u64,
        oracle_price: u64,
    ) -> Result<()> {
        // Funding settle is required for correct pnl
        self.touch_account(idx)?;
        // Best-effort mark-to-market (saturating — never wedges on extreme PnL)
        self.settle_mark_to_oracle_best_effort(idx, oracle_price)?;
        // Best-effort fees; margin check would just block the liquidation we need to do
        let _ = self.settle_maintenance_fee_best_effort_for_crank(idx, now_slot)?;
        Ok(())
    }

    /// Set owner pubkey for an account
    pub fn set_owner(&mut self, idx: u16, owner: [u8; 32]) -> Result<()> {
        if idx as usize >= MAX_ACCOUNTS || !self.is_used(idx as usize) {
            return Err(RiskError::Unauthorized);
        }
        self.accounts[idx as usize].owner = owner;
        Ok(())
    }

    /// Pre-fund fee credits for an account.
    ///
    /// The wrapper must have already transferred `amount` tokens into the vault.
    /// This pre-pays future maintenance fees: vault increases, insurance receives
    /// the amount as revenue (since credits are a coupon — spending them later
    /// does NOT re-book into insurance), and the account's fee_credits balance
    /// increases by `amount`.
    pub fn deposit_fee_credits(&mut self, idx: u16, amount: u128, now_slot: u64) -> Result<()> {
        if idx as usize >= MAX_ACCOUNTS || !self.is_used(idx as usize) {
            return Err(RiskError::Unauthorized);
        }
        self.current_slot = now_slot;

        // Wrapper transferred tokens into vault
        self.vault = self.vault + amount;

        // Pre-fund: insurance receives the amount now.
        // When credits are later spent during fee settlement, no further
        // insurance booking occurs (coupon semantics).
        self.insurance_fund.balance = self.insurance_fund.balance + amount;
        self.insurance_fund.fee_revenue = self.insurance_fund.fee_revenue + amount;

        // Credit the account
        self.accounts[idx as usize].fee_credits = self.accounts[idx as usize]
            .fee_credits
            .saturating_add(amount as i128);

        Ok(())
    }

    /// Add fee credits without vault/insurance accounting.
    /// Only for tests and Kani proofs — production code must use deposit_fee_credits.
    #[cfg(any(test, feature = "test", kani))]
    pub fn add_fee_credits(&mut self, idx: u16, amount: u128) -> Result<()> {
        if idx as usize >= MAX_ACCOUNTS || !self.is_used(idx as usize) {
            return Err(RiskError::Unauthorized);
        }
        self.accounts[idx as usize].fee_credits = self.accounts[idx as usize]
            .fee_credits
            .saturating_add(amount as i128);
        Ok(())
    }

    /// Set the risk reduction threshold (admin function).
    /// This controls when risk-reduction-only mode is triggered.
    #[inline]
    pub fn set_risk_reduction_threshold(&mut self, new_threshold: u128) {
        self.params.risk_reduction_threshold = U128::new(new_threshold);
    }

    /// Get the current risk reduction threshold.
    #[inline]
    pub fn risk_reduction_threshold(&self) -> u128 {
        self.params.risk_reduction_threshold.get()
    }

    /// Close an account and return its capital to the caller.
    ///
    /// Requirements:
    /// - Account must exist
    /// - Position must be zero (no open positions)
    /// - fee_credits >= 0 (no outstanding fees owed)
    /// - pnl must be 0 after settlement (positive pnl must be warmed up first)
    ///
    /// Returns Err(PnlNotWarmedUp) if pnl > 0 (user must wait for warmup).
    /// Returns Err(Undercollateralized) if pnl < 0 (shouldn't happen after settlement).
    /// Returns the capital amount on success.
    pub fn close_account(&mut self, idx: u16, now_slot: u64, oracle_price: u64) -> Result<u128> {
        // Update current_slot so warmup/bookkeeping progresses consistently
        self.current_slot = now_slot;

        if idx as usize >= MAX_ACCOUNTS || !self.is_used(idx as usize) {
            return Err(RiskError::AccountNotFound);
        }

        // Full settlement: funding + maintenance fees + warmup
        // This converts warmed pnl to capital and realizes negative pnl
        self.touch_account_full(idx, now_slot, oracle_price)?;

        // Position must be zero
        if !self.accounts[idx as usize].position_size.is_zero() {
            return Err(RiskError::Undercollateralized); // Has open position
        }

        // Forgive any remaining fee debt (Finding C: fee debt traps).
        // pay_fee_debt_from_capital (via touch_account_full above) already paid
        // what it could. Any remainder is uncollectable — forgive and proceed.
        if self.accounts[idx as usize].fee_credits.is_negative() {
            self.accounts[idx as usize].fee_credits = I128::ZERO;
        }

        let account = &self.accounts[idx as usize];

        // PnL must be zero to close. This enforces:
        // 1. Users can't bypass warmup by closing with positive unwarmed pnl
        // 2. Conservation is maintained (forfeiting pnl would create unbounded slack)
        // 3. Negative pnl after full settlement implies insolvency
        if account.pnl.is_positive() {
            return Err(RiskError::PnlNotWarmedUp);
        }
        if account.pnl.is_negative() {
            return Err(RiskError::Undercollateralized);
        }

        let capital = account.capital;

        // Deduct from vault
        if capital > self.vault {
            return Err(RiskError::InsufficientBalance);
        }
        self.vault = self.vault - capital;

        // Decrement c_tot before freeing slot (free_slot zeroes account but doesn't update c_tot)
        self.set_capital(idx as usize, 0);

        // Free the slot
        self.free_slot(idx);

        Ok(capital.get())
    }

    /// Free an account slot (internal helper).
    /// Clears the account, bitmap, and returns slot to freelist.
    /// Caller must ensure the account is safe to free (no capital, no positive pnl, etc).
    fn free_slot(&mut self, idx: u16) {
        self.accounts[idx as usize] = empty_account();
        self.clear_used(idx as usize);
        self.next_free[idx as usize] = self.free_head;
        self.free_head = idx;
        self.num_used_accounts = self.num_used_accounts.saturating_sub(1);
    }

    /// Garbage collect dust accounts.
    ///
    /// A "dust account" is a slot that can never pay out anything:
    /// - position_size == 0
    /// - capital == 0
    /// - reserved_pnl == 0
    /// - pnl <= 0
    ///
    /// Any remaining negative PnL is socialized via ADL waterfall before freeing.
    /// No token transfers occur - this is purely internal bookkeeping cleanup.
    ///
    /// Called at end of keeper_crank after liquidation/settlement has already run.
    ///
    /// Returns the number of accounts closed.
    pub fn garbage_collect_dust(&mut self) -> u32 {
        // Collect dust candidates: accounts with zero position, capital, reserved, and non-positive pnl
        let mut to_free: [u16; GC_CLOSE_BUDGET as usize] = [0; GC_CLOSE_BUDGET as usize];
        let mut num_to_free = 0usize;

        // Scan up to ACCOUNTS_PER_CRANK slots, capped to MAX_ACCOUNTS
        let max_scan = (ACCOUNTS_PER_CRANK as usize).min(MAX_ACCOUNTS);
        let start = self.gc_cursor as usize;

        for offset in 0..max_scan {
            // Budget check
            if num_to_free >= GC_CLOSE_BUDGET as usize {
                break;
            }

            let idx = (start + offset) & ACCOUNT_IDX_MASK;

            // Check if slot is used via bitmap
            let block = idx >> 6;
            let bit = idx & 63;
            if (self.used[block] & (1u64 << bit)) == 0 {
                continue;
            }

            // NEVER garbage collect LP accounts - they are essential for market operation
            if self.accounts[idx].is_lp() {
                continue;
            }

            // Best-effort fee settle so accounts with tiny capital get drained in THIS sweep.
            let _ = self.settle_maintenance_fee_best_effort_for_crank(idx as u16, self.current_slot);

            // Dust predicate: must have zero position, capital, reserved, and non-positive pnl
            {
                let account = &self.accounts[idx];
                if !account.position_size.is_zero() {
                    continue;
                }
                if !account.capital.is_zero() {
                    continue;
                }
                if account.reserved_pnl != 0 {
                    continue;
                }
                if account.pnl.is_positive() {
                    continue;
                }
            }

            // If flat, funding is irrelevant — snap to global so dust can be collected.
            // Position size is already confirmed zero above, so no unsettled funding value.
            if self.accounts[idx].funding_index != self.funding_index_qpb_e6 {
                self.accounts[idx].funding_index = self.funding_index_qpb_e6;
            }

            // Write off negative pnl (spec §6.1: unpayable loss just reduces Residual)
            if self.accounts[idx].pnl.is_negative() {
                self.set_pnl(idx, 0);
            }

            // Queue for freeing
            to_free[num_to_free] = idx as u16;
            num_to_free += 1;
        }

        // Update cursor for next call
        self.gc_cursor = ((start + max_scan) & ACCOUNT_IDX_MASK) as u16;

        // Free all collected dust accounts
        for i in 0..num_to_free {
            self.free_slot(to_free[i]);
        }

        num_to_free as u32
    }

    // ========================================
    // Keeper Crank
    // ========================================

    /// Check if a fresh crank is required before state-changing operations.
    /// Returns Err if the crank is stale (too old).
    pub fn require_fresh_crank(&self, now_slot: u64) -> Result<()> {
        if now_slot.saturating_sub(self.last_crank_slot) > self.max_crank_staleness_slots {
            return Err(RiskError::Unauthorized); // NeedsCrank
        }
        Ok(())
    }

    /// Check if a full sweep started recently.
    /// For risk-increasing ops, we require a sweep to have STARTED recently.
    /// The priority-liquidation phase runs every crank, so once a sweep starts,
    /// the worst accounts are immediately addressed.
    pub fn require_recent_full_sweep(&self, now_slot: u64) -> Result<()> {
        if now_slot.saturating_sub(self.last_full_sweep_start_slot) > self.max_crank_staleness_slots
        {
            return Err(RiskError::Unauthorized); // SweepStale
        }
        Ok(())
    }


    /// Check if force-realize mode is active (insurance at or below threshold).
    /// When active, keeper_crank will run windowed force-realize steps.
    #[inline]
    fn force_realize_active(&self) -> bool {
        self.insurance_fund.balance <= self.params.risk_reduction_threshold
    }

    /// Keeper crank entrypoint - advances global state and performs maintenance.
    ///
    /// Returns CrankOutcome with flags indicating what happened.
    ///
    /// Behavior:
    /// 1. Accrue funding
    /// 2. Advance last_crank_slot if now_slot > last_crank_slot
    /// 3. Settle maintenance fees for caller (50% discount)
    /// 4. Process up to ACCOUNTS_PER_CRANK occupied accounts:
    ///    - Liquidation (if not in force-realize mode)
    ///    - Force-realize (if insurance at/below threshold)
    ///    - Socialization (haircut profits to cover losses)
    ///    - LP max tracking
    /// 5. Detect and finalize full sweep completion
    ///
    /// This is the single permissionless "do-the-right-thing" entrypoint.
    /// - Always attempts caller's maintenance settle with 50% discount (best-effort)
    /// - Only advances last_crank_slot when now_slot > last_crank_slot
    /// - Returns last_cursor: the index where this crank stopped
    /// - Returns sweep_complete: true if this crank completed a full sweep
    ///
    /// When the system has fewer than ACCOUNTS_PER_CRANK accounts, one crank
    /// covers all accounts and completes a full sweep.
    pub fn keeper_crank(
        &mut self,
        caller_idx: u16,
        now_slot: u64,
        oracle_price: u64,
        funding_rate_bps_per_slot: i64,
        allow_panic: bool,
    ) -> Result<CrankOutcome> {
        // Validate oracle price bounds (prevents overflow in mark_pnl calculations)
        if oracle_price == 0 || oracle_price > MAX_ORACLE_PRICE {
            return Err(RiskError::Overflow);
        }

        // Update current_slot so warmup/bookkeeping progresses consistently
        self.current_slot = now_slot;

        // Detect if this is the start of a new sweep
        let starting_new_sweep = self.crank_cursor == self.sweep_start_idx;
        if starting_new_sweep {
            self.last_full_sweep_start_slot = now_slot;
            // Reset in-progress lp_max_abs for fresh sweep
            self.lp_max_abs_sweep = U128::ZERO;
        }

        // Accrue funding first using the STORED rate (anti-retroactivity).
        // This ensures funding charged for the elapsed interval uses the rate that was
        // in effect at the start of the interval, NOT the new rate computed from current state.
        self.accrue_funding(now_slot, oracle_price)?;

        // Now set the new rate for the NEXT interval (anti-retroactivity).
        // The funding_rate_bps_per_slot parameter becomes the rate for [now_slot, next_accrual).
        self.set_funding_rate_for_next_interval(funding_rate_bps_per_slot);

        // Check if we're advancing the global crank slot
        let advanced = now_slot > self.last_crank_slot;
        if advanced {
            self.last_crank_slot = now_slot;
        }

        // Always attempt caller's maintenance settle (best-effort, no timestamp games)
        let (slots_forgiven, caller_settle_ok) = if (caller_idx as usize) < MAX_ACCOUNTS
            && self.is_used(caller_idx as usize)
        {
            let last_fee = self.accounts[caller_idx as usize].last_fee_slot;
            let dt = now_slot.saturating_sub(last_fee);
            let forgive = dt / 2;

            if forgive > 0 && dt > 0 {
                self.accounts[caller_idx as usize].last_fee_slot = last_fee.saturating_add(forgive);
            }
            let settle_result =
                self.settle_maintenance_fee_best_effort_for_crank(caller_idx, now_slot);
            (forgive, settle_result.is_ok())
        } else {
            (0, true)
        };

        // Detect conditions for informational flags (before processing)
        let force_realize_active = self.force_realize_active();

        // Process up to ACCOUNTS_PER_CRANK occupied accounts
        let mut num_liquidations: u32 = 0;
        let mut num_liq_errors: u16 = 0;
        let mut force_realize_closed: u16 = 0;
        let mut force_realize_errors: u16 = 0;
        let mut sweep_complete = false;
        let mut accounts_processed: u16 = 0;
        let mut liq_budget = LIQ_BUDGET_PER_CRANK;
        let mut force_realize_budget = FORCE_REALIZE_BUDGET_PER_CRANK;

        let start_cursor = self.crank_cursor;

        // Iterate through index space looking for occupied accounts
        let mut idx = self.crank_cursor as usize;
        let mut slots_scanned: usize = 0;

        while accounts_processed < ACCOUNTS_PER_CRANK && slots_scanned < MAX_ACCOUNTS {
            slots_scanned += 1;

            // Check if slot is used
            let block = idx >> 6;
            let bit = idx & 63;
            let is_occupied = (self.used[block] & (1u64 << bit)) != 0;

            if is_occupied {
                accounts_processed += 1;

                // Always settle maintenance fees for every visited account.
                // This drains idle accounts over time so they eventually become dust.
                let _ = self.settle_maintenance_fee_best_effort_for_crank(idx as u16, now_slot);
                // Touch account and settle warmup to drain abandoned positive PnL
                let _ = self.touch_account(idx as u16);
                self.settle_warmup_to_capital_for_crank(idx as u16);

                // === Liquidation (if not in force-realize mode) ===
                if !force_realize_active && liq_budget > 0 {
                    if !self.accounts[idx].position_size.is_zero() {
                        match self.liquidate_at_oracle(idx as u16, now_slot, oracle_price) {
                            Ok(true) => {
                                num_liquidations += 1;
                                liq_budget = liq_budget.saturating_sub(1);
                            }
                            Ok(false) => {}
                            Err(_) => {
                                num_liq_errors += 1;
                            }
                        }
                    }

                    // Force-close negative equity or dust positions
                    if !self.accounts[idx].position_size.is_zero() {
                        let equity =
                            self.account_equity_mtm_at_oracle(&self.accounts[idx], oracle_price);
                        let abs_pos = self.accounts[idx].position_size.unsigned_abs();
                        let is_dust = abs_pos < self.params.min_liquidation_abs.get();

                        if equity == 0 || is_dust {
                            // Force close: settle mark, close position, write off loss
                            let _ = self.touch_account_for_liquidation(idx as u16, now_slot, oracle_price);
                            let _ = self.oracle_close_position_core(idx as u16, oracle_price);
                            self.lifetime_force_realize_closes =
                                self.lifetime_force_realize_closes.saturating_add(1);
                        }
                    }
                }

                // === Force-realize (when insurance at/below threshold) ===
                if force_realize_active && force_realize_budget > 0 {
                    if !self.accounts[idx].position_size.is_zero() {
                        if self
                            .touch_account_for_force_realize(idx as u16, now_slot, oracle_price)
                            .is_ok()
                        {
                            if self.oracle_close_position_core(idx as u16, oracle_price).is_ok() {
                                force_realize_closed += 1;
                                force_realize_budget = force_realize_budget.saturating_sub(1);
                                self.lifetime_force_realize_closes =
                                    self.lifetime_force_realize_closes.saturating_add(1);
                            } else {
                                force_realize_errors += 1;
                            }
                        } else {
                            force_realize_errors += 1;
                        }
                    }
                }

                // === LP max tracking ===
                if self.accounts[idx].is_lp() {
                    let abs_pos = self.accounts[idx].position_size.unsigned_abs();
                    self.lp_max_abs_sweep = self.lp_max_abs_sweep.max(U128::new(abs_pos));
                }
            }

            // Advance to next index (with wrap)
            idx = (idx + 1) & ACCOUNT_IDX_MASK;

            // Check for sweep completion: we've wrapped around to sweep_start_idx
            // (and we've actually processed some slots, not just starting)
            if idx == self.sweep_start_idx as usize && slots_scanned > 0 {
                sweep_complete = true;
                break;
            }
        }

        // Update cursor for next crank
        self.crank_cursor = idx as u16;

        // If sweep complete, finalize
        if sweep_complete {
            self.last_full_sweep_completed_slot = now_slot;
            self.lp_max_abs = self.lp_max_abs_sweep;
            self.sweep_start_idx = self.crank_cursor;
        }

        // Garbage collect dust accounts
        let num_gc_closed = self.garbage_collect_dust();

        // Detect conditions for informational flags
        let force_realize_needed = self.force_realize_active();
        let panic_needed = false; // No longer needed with haircut ratio

        Ok(CrankOutcome {
            advanced,
            slots_forgiven,
            caller_settle_ok,
            force_realize_needed,
            panic_needed,
            num_liquidations,
            num_liq_errors,
            num_gc_closed,
            force_realize_closed,
            force_realize_errors,
            last_cursor: self.crank_cursor,
            sweep_complete,
        })
    }

    // ========================================
    // Liquidation
    // ========================================

    /// Compute mark PnL for a position at oracle price (pure helper, no side effects).
    /// Returns the PnL from closing the position at oracle price.
    /// - Longs: profit when oracle > entry
    /// - Shorts: profit when entry > oracle
    pub fn mark_pnl_for_position(pos: i128, entry: u64, oracle: u64) -> Result<i128> {
        if pos == 0 {
            return Ok(0);
        }

        let abs_pos = saturating_abs_i128(pos) as u128;

        let diff: i128 = if pos > 0 {
            // Long: profit when oracle > entry
            (oracle as i128).saturating_sub(entry as i128)
        } else {
            // Short: profit when entry > oracle
            (entry as i128).saturating_sub(oracle as i128)
        };

        // mark_pnl = diff * abs_pos / 1_000_000
        diff.checked_mul(abs_pos as i128)
            .ok_or(RiskError::Overflow)?
            .checked_div(1_000_000)
            .ok_or(RiskError::Overflow)
    }

    /// Compute how much position to close for liquidation (closed-form, single-pass).
    ///
    /// Returns (close_abs, is_full_close) where:
    /// - close_abs = absolute position size to close
    /// - is_full_close = true if this is a full position close (including dust kill-switch)
    ///
    /// ## Algorithm:
    /// 1. Compute target_bps = maintenance_margin_bps + liquidation_buffer_bps
    /// 2. Compute max safe remaining position: abs_pos_safe_max = floor(E_mtm * 10_000 * 1_000_000 / (P * target_bps))
    /// 3. close_abs = abs_pos - abs_pos_safe_max
    /// 4. If remaining position < min_liquidation_abs, do full close (dust kill-switch)
    ///
    /// Uses MTM equity (capital + realized_pnl + mark_pnl) for correct risk calculation.
    /// This is deterministic, requires no iteration, and guarantees single-pass liquidation.
    pub fn compute_liquidation_close_amount(
        &self,
        account: &Account,
        oracle_price: u64,
    ) -> (u128, bool) {
        let abs_pos = saturating_abs_i128(account.position_size.get()) as u128;
        if abs_pos == 0 {
            return (0, false);
        }

        // MTM equity at oracle price (fail-safe: overflow returns 0 = full liquidation)
        let equity = self.account_equity_mtm_at_oracle(account, oracle_price);

        // Target margin = maintenance + buffer (in basis points)
        let target_bps = self
            .params
            .maintenance_margin_bps
            .saturating_add(self.params.liquidation_buffer_bps);

        // Maximum safe remaining position (floor-safe calculation)
        // abs_pos_safe_max = floor(equity * 10_000 * 1_000_000 / (oracle_price * target_bps))
        // Rearranged to avoid intermediate overflow:
        // abs_pos_safe_max = floor(equity * 10_000_000_000 / (oracle_price * target_bps))
        let numerator = mul_u128(equity, 10_000_000_000);
        let denominator = mul_u128(oracle_price as u128, target_bps as u128);

        let mut abs_pos_safe_max = if denominator == 0 {
            0 // Edge case: full liquidation if no denominator
        } else {
            numerator / denominator
        };

        // Clamp to current position (can't have safe max > actual position)
        abs_pos_safe_max = core::cmp::min(abs_pos_safe_max, abs_pos);

        // Conservative rounding guard: subtract 1 unit to ensure we close slightly more
        // than mathematically required. This guarantees post-liquidation account is
        // strictly on the safe side of the inequality despite integer truncation.
        if abs_pos_safe_max > 0 {
            abs_pos_safe_max -= 1;
        }

        // Required close amount
        let close_abs = abs_pos.saturating_sub(abs_pos_safe_max);

        // Dust kill-switch: if remaining position would be below min, do full close
        let remaining = abs_pos.saturating_sub(close_abs);
        if remaining < self.params.min_liquidation_abs.get() {
            return (abs_pos, true); // Full close
        }

        (close_abs, close_abs == abs_pos)
    }

    /// Core helper for closing a SLICE of a position at oracle price (partial liquidation).
    ///
    /// Similar to oracle_close_position_core but:
    /// - Only closes `close_abs` units of position (not the entire position)
    /// - Computes proportional mark_pnl for the closed slice
    /// - Entry price remains unchanged (correct for same-direction partial reduction)
    ///
    /// ## PnL Routing (same invariant as full close):
    /// - mark_pnl > 0 (profit) → backed by haircut ratio h (no ADL needed)
    /// - mark_pnl <= 0 (loss) → realized via settle_warmup_to_capital (capital path)
    /// - Residual negative PnL (capital exhausted) → written off via set_pnl(i, 0) (spec §6.1)
    ///
    /// ASSUMES: Caller has already called touch_account_full() on this account.
    fn oracle_close_position_slice_core(
        &mut self,
        idx: u16,
        oracle_price: u64,
        close_abs: u128,
    ) -> Result<ClosedOutcome> {
        let pos = self.accounts[idx as usize].position_size.get();
        let current_abs_pos = saturating_abs_i128(pos) as u128;

        if close_abs == 0 || current_abs_pos == 0 {
            return Ok(ClosedOutcome {
                abs_pos: 0,
                mark_pnl: 0,
                cap_before: self.accounts[idx as usize].capital.get(),
                cap_after: self.accounts[idx as usize].capital.get(),
                position_was_closed: false,
            });
        }

        if close_abs >= current_abs_pos {
            return self.oracle_close_position_core(idx, oracle_price);
        }

        let entry = self.accounts[idx as usize].entry_price;
        let cap_before = self.accounts[idx as usize].capital.get();

        let diff: i128 = if pos > 0 {
            (oracle_price as i128).saturating_sub(entry as i128)
        } else {
            (entry as i128).saturating_sub(oracle_price as i128)
        };

        let mark_pnl = match diff
            .checked_mul(close_abs as i128)
            .and_then(|v| v.checked_div(1_000_000))
        {
            Some(pnl) => pnl,
            None => -u128_to_i128_clamped(cap_before),
        };

        // Apply mark PnL via set_pnl (maintains pnl_pos_tot aggregate)
        let new_pnl = self.accounts[idx as usize].pnl.get().saturating_add(mark_pnl);
        self.set_pnl(idx as usize, new_pnl);

        // Update position
        let new_abs_pos = current_abs_pos.saturating_sub(close_abs);
        self.accounts[idx as usize].position_size = if pos > 0 {
            I128::new(new_abs_pos as i128)
        } else {
            I128::new(-(new_abs_pos as i128))
        };

        // Update OI
        self.total_open_interest = self.total_open_interest - close_abs;

        // Update LP aggregates if LP
        if self.accounts[idx as usize].is_lp() {
            let new_pos = self.accounts[idx as usize].position_size.get();
            self.net_lp_pos = self.net_lp_pos - pos + new_pos;
            self.lp_sum_abs = self.lp_sum_abs - close_abs;
        }

        // Settle warmup (loss settlement + profit conversion per spec §6)
        self.settle_warmup_to_capital(idx)?;

        // Write off residual negative PnL (capital exhausted) per spec §6.1
        if self.accounts[idx as usize].pnl.is_negative() {
            self.set_pnl(idx as usize, 0);
        }

        let cap_after = self.accounts[idx as usize].capital.get();

        Ok(ClosedOutcome {
            abs_pos: close_abs,
            mark_pnl,
            cap_before,
            cap_after,
            position_was_closed: true,
        })
    }

    /// Core helper for oracle-price full position close (spec §6).
    ///
    /// Applies mark PnL, closes position, settles warmup, writes off unpayable loss.
    /// No ADL needed — undercollateralization is reflected via haircut ratio h.
    ///
    /// ASSUMES: Caller has already called touch_account_full() on this account.
    fn oracle_close_position_core(&mut self, idx: u16, oracle_price: u64) -> Result<ClosedOutcome> {
        if self.accounts[idx as usize].position_size.is_zero() {
            return Ok(ClosedOutcome {
                abs_pos: 0,
                mark_pnl: 0,
                cap_before: self.accounts[idx as usize].capital.get(),
                cap_after: self.accounts[idx as usize].capital.get(),
                position_was_closed: false,
            });
        }

        let pos = self.accounts[idx as usize].position_size.get();
        let abs_pos = saturating_abs_i128(pos) as u128;
        let entry = self.accounts[idx as usize].entry_price;
        let cap_before = self.accounts[idx as usize].capital.get();

        let mark_pnl = match Self::mark_pnl_for_position(pos, entry, oracle_price) {
            Ok(pnl) => pnl,
            Err(_) => -u128_to_i128_clamped(cap_before),
        };

        // Apply mark PnL via set_pnl (maintains pnl_pos_tot aggregate)
        let new_pnl = self.accounts[idx as usize].pnl.get().saturating_add(mark_pnl);
        self.set_pnl(idx as usize, new_pnl);

        // Close position
        self.accounts[idx as usize].position_size = I128::ZERO;
        self.accounts[idx as usize].entry_price = oracle_price;

        // Update OI
        self.total_open_interest = self.total_open_interest - abs_pos;

        // Update LP aggregates if LP
        if self.accounts[idx as usize].is_lp() {
            self.net_lp_pos = self.net_lp_pos - pos;
            self.lp_sum_abs = self.lp_sum_abs - abs_pos;
        }

        // Settle warmup (loss settlement + profit conversion per spec §6)
        self.settle_warmup_to_capital(idx)?;

        // Write off residual negative PnL (capital exhausted) per spec §6.1
        if self.accounts[idx as usize].pnl.is_negative() {
            self.set_pnl(idx as usize, 0);
        }

        let cap_after = self.accounts[idx as usize].capital.get();

        Ok(ClosedOutcome {
            abs_pos,
            mark_pnl,
            cap_before,
            cap_after,
            position_was_closed: true,
        })
    }

    /// Liquidate a single account at oracle price if below maintenance margin.
    ///
    /// Returns Ok(true) if liquidation occurred, Ok(false) if not needed/possible.
    /// Per spec: close position, settle losses, write off unpayable PnL, charge fee.
    /// No ADL — haircut ratio h reflects any undercollateralization.
    pub fn liquidate_at_oracle(
        &mut self,
        idx: u16,
        now_slot: u64,
        oracle_price: u64,
    ) -> Result<bool> {
        self.current_slot = now_slot;

        if (idx as usize) >= MAX_ACCOUNTS || !self.is_used(idx as usize) {
            return Ok(false);
        }

        if oracle_price == 0 || oracle_price > MAX_ORACLE_PRICE {
            return Err(RiskError::Overflow);
        }

        if self.accounts[idx as usize].position_size.is_zero() {
            return Ok(false);
        }

        // Settle funding + mark-to-market + best-effort fees
        self.touch_account_for_liquidation(idx, now_slot, oracle_price)?;

        let account = &self.accounts[idx as usize];
        if self.is_above_maintenance_margin_mtm(account, oracle_price) {
            return Ok(false);
        }

        let (close_abs, is_full_close) =
            self.compute_liquidation_close_amount(account, oracle_price);

        if close_abs == 0 {
            return Ok(false);
        }

        // Close position (no ADL — losses written off in close helper)
        let mut outcome = if is_full_close {
            self.oracle_close_position_core(idx, oracle_price)?
        } else {
            match self.oracle_close_position_slice_core(idx, oracle_price, close_abs) {
                Ok(r) => r,
                Err(RiskError::Overflow) => {
                    self.oracle_close_position_core(idx, oracle_price)?
                }
                Err(e) => return Err(e),
            }
        };

        if !outcome.position_was_closed {
            return Ok(false);
        }

        // Safety check: if position remains and still below target, full close
        if !self.accounts[idx as usize].position_size.is_zero() {
            let target_bps = self
                .params
                .maintenance_margin_bps
                .saturating_add(self.params.liquidation_buffer_bps);
            if !self.is_above_margin_bps_mtm(&self.accounts[idx as usize], oracle_price, target_bps)
            {
                let fallback = self.oracle_close_position_core(idx, oracle_price)?;
                if fallback.position_was_closed {
                    outcome.abs_pos = outcome.abs_pos.saturating_add(fallback.abs_pos);
                }
            }
        }

        // Charge liquidation fee (from remaining capital → insurance)
        // Use ceiling division for consistency with trade fees
        let notional = mul_u128(outcome.abs_pos, oracle_price as u128) / 1_000_000;
        let fee_raw = if notional > 0 && self.params.liquidation_fee_bps > 0 {
            (mul_u128(notional, self.params.liquidation_fee_bps as u128) + 9999) / 10_000
        } else {
            0
        };
        let fee = core::cmp::min(fee_raw, self.params.liquidation_fee_cap.get());
        let account_capital = self.accounts[idx as usize].capital.get();
        let pay = core::cmp::min(fee, account_capital);

        self.set_capital(idx as usize, account_capital.saturating_sub(pay));
        self.insurance_fund.balance = self.insurance_fund.balance.saturating_add_u128(U128::new(pay));
        self.insurance_fund.fee_revenue = self.insurance_fund.fee_revenue.saturating_add_u128(U128::new(pay));

        self.lifetime_liquidations = self.lifetime_liquidations.saturating_add(1);

        Ok(true)
    }

    // ========================================
    // Warmup
    // ========================================

    /// Calculate withdrawable PNL for an account after warmup
    pub fn withdrawable_pnl(&self, account: &Account) -> u128 {
        // Only positive PNL can be withdrawn
        let positive_pnl = clamp_pos_i128(account.pnl.get());

        // Available = positive PNL - reserved
        let available_pnl = sub_u128(positive_pnl, account.reserved_pnl as u128);

        let effective_slot = self.current_slot;

        // Calculate elapsed slots
        let elapsed_slots = effective_slot.saturating_sub(account.warmup_started_at_slot);

        // Calculate warmed up cap: slope * elapsed_slots
        let warmed_up_cap = mul_u128(account.warmup_slope_per_step.get(), elapsed_slots as u128);

        // Return minimum of available and warmed up
        core::cmp::min(available_pnl, warmed_up_cap)
    }

    /// Update warmup slope for an account
    /// NOTE: No warmup rate cap (removed for simplicity)
    pub fn update_warmup_slope(&mut self, idx: u16) -> Result<()> {
        if !self.is_used(idx as usize) {
            return Err(RiskError::AccountNotFound);
        }

        let account = &mut self.accounts[idx as usize];

        // Calculate available gross PnL: AvailGross_i = max(PNL_i, 0) - R_i (spec §5)
        let positive_pnl = clamp_pos_i128(account.pnl.get());
        let avail_gross = sub_u128(positive_pnl, account.reserved_pnl as u128);

        // Calculate slope: avail_gross / warmup_period
        // Ensure slope >= 1 when avail_gross > 0 to prevent "zero forever" bug
        let slope = if self.params.warmup_period_slots > 0 {
            let base = avail_gross / (self.params.warmup_period_slots as u128);
            if avail_gross > 0 {
                core::cmp::max(1, base)
            } else {
                0
            }
        } else {
            avail_gross // Instant warmup if period is 0
        };

        // Verify slope >= 1 when available PnL exists
        #[cfg(any(test, kani))]
        debug_assert!(
            slope >= 1 || avail_gross == 0,
            "Warmup slope bug: slope {} with avail_gross {}",
            slope,
            avail_gross
        );

        // Update slope
        account.warmup_slope_per_step = U128::new(slope);

        account.warmup_started_at_slot = self.current_slot;

        Ok(())
    }

    // ========================================
    // Funding
    // ========================================

    /// Accrue funding globally in O(1) using the stored rate (anti-retroactivity).
    ///
    /// This uses `funding_rate_bps_per_slot_last` - the rate in effect since `last_funding_slot`.
    /// The rate for the NEXT interval is set separately via `set_funding_rate_for_next_interval`.
    ///
    /// Anti-retroactivity guarantee: state changes at slot t can only affect funding for slots >= t.
    pub fn accrue_funding(&mut self, now_slot: u64, oracle_price: u64) -> Result<()> {
        let dt = now_slot.saturating_sub(self.last_funding_slot);
        if dt == 0 {
            return Ok(());
        }

        // Input validation to prevent overflow
        if oracle_price == 0 || oracle_price > MAX_ORACLE_PRICE {
            return Err(RiskError::Overflow);
        }

        // Use the STORED rate (anti-retroactivity: rate was set at start of interval)
        let funding_rate = self.funding_rate_bps_per_slot_last;

        // Cap funding rate at 10000 bps (100%) per slot as sanity bound
        // Real-world funding rates should be much smaller (typically < 1 bps/slot)
        if funding_rate.abs() > 10_000 {
            return Err(RiskError::Overflow);
        }

        if dt > 31_536_000 {
            return Err(RiskError::Overflow);
        }

        // Use checked math to prevent silent overflow
        let price = oracle_price as i128;
        let rate = funding_rate as i128;
        let dt_i = dt as i128;

        // ΔF = price × rate × dt / 10,000
        let delta = price
            .checked_mul(rate)
            .ok_or(RiskError::Overflow)?
            .checked_mul(dt_i)
            .ok_or(RiskError::Overflow)?
            .checked_div(10_000)
            .ok_or(RiskError::Overflow)?;

        self.funding_index_qpb_e6 = self
            .funding_index_qpb_e6
            .checked_add(delta)
            .ok_or(RiskError::Overflow)?;

        self.last_funding_slot = now_slot;
        Ok(())
    }

    /// Set the funding rate for the NEXT interval (anti-retroactivity).
    ///
    /// MUST be called AFTER `accrue_funding()` to ensure the old rate is applied to
    /// the elapsed interval before storing the new rate.
    ///
    /// This implements the "rate-change rule" from the spec: state changes at slot t
    /// can only affect funding for slots >= t.
    pub fn set_funding_rate_for_next_interval(&mut self, new_rate_bps_per_slot: i64) {
        self.funding_rate_bps_per_slot_last = new_rate_bps_per_slot;
    }

    /// Convenience: Set rate then accrue in one call.
    ///
    /// This sets the rate for the interval being accrued, then accrues.
    /// For proper anti-retroactivity in production, the rate should be set at the
    /// START of an interval via `set_funding_rate_for_next_interval`, then accrued later.
    pub fn accrue_funding_with_rate(
        &mut self,
        now_slot: u64,
        oracle_price: u64,
        funding_rate_bps_per_slot: i64,
    ) -> Result<()> {
        self.set_funding_rate_for_next_interval(funding_rate_bps_per_slot);
        self.accrue_funding(now_slot, oracle_price)
    }

    /// Settle funding for an account (lazy update).
    /// Uses set_pnl helper to maintain pnl_pos_tot aggregate (spec §4.2).
    fn settle_account_funding(&mut self, idx: usize) -> Result<()> {
        let global_fi = self.funding_index_qpb_e6;
        let account = &self.accounts[idx];
        let delta_f = global_fi
            .get()
            .checked_sub(account.funding_index.get())
            .ok_or(RiskError::Overflow)?;

        if delta_f != 0 && !account.position_size.is_zero() {
            // payment = position × ΔF / 1e6
            // Round UP for positive payments (account pays), truncate for negative (account receives)
            // This ensures vault always has at least what's owed (one-sided conservation slack).
            let raw = account
                .position_size
                .get()
                .checked_mul(delta_f)
                .ok_or(RiskError::Overflow)?;

            let payment = if raw > 0 {
                // Account is paying: round UP to ensure vault gets at least theoretical amount
                raw.checked_add(999_999)
                    .ok_or(RiskError::Overflow)?
                    .checked_div(1_000_000)
                    .ok_or(RiskError::Overflow)?
            } else {
                // Account is receiving: truncate towards zero to give at most theoretical amount
                raw.checked_div(1_000_000).ok_or(RiskError::Overflow)?
            };

            // Longs pay when funding positive: pnl -= payment
            // Use set_pnl helper to maintain pnl_pos_tot aggregate (spec §4.2)
            let new_pnl = self.accounts[idx]
                .pnl
                .get()
                .checked_sub(payment)
                .ok_or(RiskError::Overflow)?;
            self.set_pnl(idx, new_pnl);
        }

        self.accounts[idx].funding_index = global_fi;
        Ok(())
    }

    /// Touch an account (settle funding before operations)
    pub fn touch_account(&mut self, idx: u16) -> Result<()> {
        if !self.is_used(idx as usize) {
            return Err(RiskError::AccountNotFound);
        }

        self.settle_account_funding(idx as usize)
    }

    /// Settle mark-to-market PnL to the current oracle price (variation margin).
    ///
    /// This realizes all unrealized PnL at the given oracle price and resets
    /// entry_price = oracle_price. After calling this, mark_pnl_for_position
    /// will return 0 for this account at this oracle price.
    ///
    /// This makes positions fungible: any LP can close any user's position
    /// because PnL is settled to a common reference price.
    pub fn settle_mark_to_oracle(&mut self, idx: u16, oracle_price: u64) -> Result<()> {
        if idx as usize >= MAX_ACCOUNTS || !self.is_used(idx as usize) {
            return Err(RiskError::AccountNotFound);
        }

        if self.accounts[idx as usize].position_size.is_zero() {
            // No position: just set entry to oracle for determinism
            self.accounts[idx as usize].entry_price = oracle_price;
            return Ok(());
        }

        // Compute mark PnL at current oracle
        let mark = Self::mark_pnl_for_position(
            self.accounts[idx as usize].position_size.get(),
            self.accounts[idx as usize].entry_price,
            oracle_price,
        )?;

        // Realize the mark PnL via set_pnl (maintains pnl_pos_tot)
        let new_pnl = self.accounts[idx as usize]
            .pnl
            .get()
            .checked_add(mark)
            .ok_or(RiskError::Overflow)?;
        self.set_pnl(idx as usize, new_pnl);

        // Reset entry to oracle (mark PnL is now 0 at this price)
        self.accounts[idx as usize].entry_price = oracle_price;

        Ok(())
    }

    /// Best-effort mark-to-oracle settlement that uses saturating_add instead of
    /// checked_add, so it never fails on overflow.  This prevents the liquidation
    /// path from wedging on extreme mark PnL values.
    fn settle_mark_to_oracle_best_effort(&mut self, idx: u16, oracle_price: u64) -> Result<()> {
        if idx as usize >= MAX_ACCOUNTS || !self.is_used(idx as usize) {
            return Err(RiskError::AccountNotFound);
        }

        if self.accounts[idx as usize].position_size.is_zero() {
            self.accounts[idx as usize].entry_price = oracle_price;
            return Ok(());
        }

        // Compute mark PnL at current oracle
        let mark = Self::mark_pnl_for_position(
            self.accounts[idx as usize].position_size.get(),
            self.accounts[idx as usize].entry_price,
            oracle_price,
        )?;

        // Realize the mark PnL via set_pnl (saturating — never fails on overflow)
        let new_pnl = self.accounts[idx as usize].pnl.get().saturating_add(mark);
        self.set_pnl(idx as usize, new_pnl);

        // Reset entry to oracle (mark PnL is now 0 at this price)
        self.accounts[idx as usize].entry_price = oracle_price;

        Ok(())
    }

    /// Full account touch: funding + mark settlement + maintenance fees + warmup.
    /// This is the standard "lazy settlement" path called on every user operation.
    /// Triggers liquidation check if fees push account below maintenance margin.
    pub fn touch_account_full(&mut self, idx: u16, now_slot: u64, oracle_price: u64) -> Result<()> {
        // Update current_slot for consistent warmup/bookkeeping
        self.current_slot = now_slot;

        // 1. Settle funding
        self.touch_account(idx)?;

        // 2. Settle mark-to-market (variation margin)
        // Per spec §5.4: if AvailGross increases, warmup must restart.
        // Capture old AvailGross before mark settlement.
        let old_avail_gross = {
            let pnl = self.accounts[idx as usize].pnl.get();
            if pnl > 0 {
                (pnl as u128).saturating_sub(self.accounts[idx as usize].reserved_pnl as u128)
            } else {
                0
            }
        };
        self.settle_mark_to_oracle(idx, oracle_price)?;
        // If AvailGross increased, update warmup slope (restarts warmup timer)
        let new_avail_gross = {
            let pnl = self.accounts[idx as usize].pnl.get();
            if pnl > 0 {
                (pnl as u128).saturating_sub(self.accounts[idx as usize].reserved_pnl as u128)
            } else {
                0
            }
        };
        if new_avail_gross > old_avail_gross {
            self.update_warmup_slope(idx)?;
        }

        // 3. Settle maintenance fees (may trigger undercollateralized error)
        self.settle_maintenance_fee(idx, now_slot, oracle_price)?;

        // 4. Settle warmup (convert warmed PnL to capital, realize losses)
        self.settle_warmup_to_capital(idx)?;

        // 5. Sweep any fee debt from newly-available capital (warmup may
        //    have created capital that should pay outstanding fee debt)
        self.pay_fee_debt_from_capital(idx);

        // 6. Re-check maintenance margin after fee debt sweep
        if !self.accounts[idx as usize].position_size.is_zero() {
            if !self.is_above_maintenance_margin_mtm(
                &self.accounts[idx as usize],
                oracle_price,
            ) {
                return Err(RiskError::Undercollateralized);
            }
        }

        Ok(())
    }

    /// Minimal touch for crank liquidations: funding + maintenance only.
    /// Skips warmup settlement for performance - losses are handled inline
    /// by the deferred close helpers, positive warmup left for user ops.
    fn touch_account_for_crank(
        &mut self,
        idx: u16,
        now_slot: u64,
        oracle_price: u64,
    ) -> Result<()> {
        // 1. Settle funding
        self.touch_account(idx)?;

        // 2. Settle maintenance fees (may trigger undercollateralized error)
        self.settle_maintenance_fee(idx, now_slot, oracle_price)?;

        // NOTE: No warmup settlement - handled inline for losses in close helpers
        Ok(())
    }

    // ========================================
    // Deposits and Withdrawals
    // ========================================

    /// Deposit funds to account.
    ///
    /// Settles any accrued maintenance fees from the deposit first,
    /// with the remainder added to capital. This ensures fee conservation
    /// (fees are never forgiven) and prevents stuck accounts.
    pub fn deposit(&mut self, idx: u16, amount: u128, now_slot: u64) -> Result<()> {
        // Update current_slot so warmup/bookkeeping progresses consistently
        self.current_slot = now_slot;

        if !self.is_used(idx as usize) {
            return Err(RiskError::AccountNotFound);
        }

        let account = &mut self.accounts[idx as usize];
        let mut deposit_remaining = amount;

        // Calculate and settle accrued fees
        let dt = now_slot.saturating_sub(account.last_fee_slot);
        if dt > 0 {
            let due = self
                .params
                .maintenance_fee_per_slot
                .get()
                .saturating_mul(dt as u128);
            account.last_fee_slot = now_slot;

            // Deduct from fee_credits (coupon: no insurance booking here —
            // insurance was already paid when credits were granted)
            account.fee_credits = account.fee_credits.saturating_sub(due as i128);
        }

        // Pay any owed fees from deposit first
        if account.fee_credits.is_negative() {
            let owed = neg_i128_to_u128(account.fee_credits.get());
            let pay = core::cmp::min(owed, deposit_remaining);

            deposit_remaining -= pay;
            self.insurance_fund.balance = self.insurance_fund.balance + pay;
            self.insurance_fund.fee_revenue = self.insurance_fund.fee_revenue + pay;

            // Credit back what was paid
            account.fee_credits = account.fee_credits.saturating_add(pay as i128);
        }

        // Vault gets full deposit (tokens received)
        self.vault = U128::new(add_u128(self.vault.get(), amount));

        // Capital gets remainder after fees (via set_capital to maintain c_tot)
        let new_cap = add_u128(self.accounts[idx as usize].capital.get(), deposit_remaining);
        self.set_capital(idx as usize, new_cap);

        // Settle warmup after deposit (allows losses to be paid promptly if underwater)
        self.settle_warmup_to_capital(idx)?;

        // If any older fee debt remains, use capital to pay it now.
        self.pay_fee_debt_from_capital(idx);

        Ok(())
    }

    /// Withdraw capital from an account.
    /// Relies on Solana transaction atomicity: if this returns Err, the entire TX aborts.
    pub fn withdraw(
        &mut self,
        idx: u16,
        amount: u128,
        now_slot: u64,
        oracle_price: u64,
    ) -> Result<()> {
        // Update current_slot so warmup/bookkeeping progresses consistently
        self.current_slot = now_slot;

        // Validate oracle price bounds (prevents overflow in mark_pnl calculations)
        if oracle_price == 0 || oracle_price > MAX_ORACLE_PRICE {
            return Err(RiskError::Overflow);
        }

        // Require fresh crank (time-based) before state-changing operations
        self.require_fresh_crank(now_slot)?;

        // Require recent full sweep started
        self.require_recent_full_sweep(now_slot)?;

        // Validate account exists
        if !self.is_used(idx as usize) {
            return Err(RiskError::AccountNotFound);
        }

        // Full settlement: funding + maintenance fees + warmup
        self.touch_account_full(idx, now_slot, oracle_price)?;

        // Read account state (scope the borrow)
        let (old_capital, pnl, position_size, entry_price, fee_credits) = {
            let account = &self.accounts[idx as usize];
            (
                account.capital,
                account.pnl,
                account.position_size,
                account.entry_price,
                account.fee_credits,
            )
        };

        // Check we have enough capital
        if old_capital.get() < amount {
            return Err(RiskError::InsufficientBalance);
        }

        // Calculate MTM equity after withdrawal with haircut (spec §3.3)
        // equity_mtm = max(0, new_capital + min(pnl, 0) + effective_pos_pnl(pnl) + mark_pnl)
        // Fail-safe: if mark_pnl overflows (corrupted entry_price/position_size), treat as 0 equity
        let new_capital = sub_u128(old_capital.get(), amount);
        let new_equity_mtm = {
            let eq = match Self::mark_pnl_for_position(position_size.get(), entry_price, oracle_price)
            {
                Ok(mark_pnl) => {
                    let cap_i = u128_to_i128_clamped(new_capital);
                    let neg_pnl = core::cmp::min(pnl.get(), 0);
                    let eff_pos = self.effective_pos_pnl(pnl.get());
                    let new_eq_i = cap_i
                        .saturating_add(neg_pnl)
                        .saturating_add(u128_to_i128_clamped(eff_pos))
                        .saturating_add(mark_pnl);
                    if new_eq_i > 0 {
                        new_eq_i as u128
                    } else {
                        0
                    }
                }
                Err(_) => 0, // Overflow => worst-case equity => will fail margin check below
            };
            // Subtract fee debt (negative fee_credits = unpaid maintenance fees)
            let fee_debt = if fee_credits.is_negative() {
                neg_i128_to_u128(fee_credits.get())
            } else {
                0
            };
            eq.saturating_sub(fee_debt)
        };

        // If account has position, must maintain initial margin at ORACLE price (MTM check)
        // This prevents withdrawing to a state that's immediately liquidatable
        if !position_size.is_zero() {
            let position_notional = mul_u128(
                saturating_abs_i128(position_size.get()) as u128,
                oracle_price as u128,
            ) / 1_000_000;

            let initial_margin_required =
                mul_u128(position_notional, self.params.initial_margin_bps as u128) / 10_000;

            if new_equity_mtm < initial_margin_required {
                return Err(RiskError::Undercollateralized);
            }
        }

        // Commit the withdrawal (via set_capital to maintain c_tot)
        self.set_capital(idx as usize, new_capital);
        self.vault = U128::new(sub_u128(self.vault.get(), amount));

        // Post-withdrawal MTM maintenance margin check at oracle price
        // This is a safety belt to ensure we never leave an account in liquidatable state
        if !self.accounts[idx as usize].position_size.is_zero() {
            if !self.is_above_maintenance_margin_mtm(&self.accounts[idx as usize], oracle_price) {
                // Revert the withdrawal (via set_capital to maintain c_tot)
                self.set_capital(idx as usize, old_capital.get());
                self.vault = U128::new(add_u128(self.vault.get(), amount));
                return Err(RiskError::Undercollateralized);
            }
        }

        // Regression assert: after settle + withdraw, negative PnL should have been settled
        #[cfg(any(test, kani))]
        debug_assert!(
            !self.accounts[idx as usize].pnl.is_negative()
                || self.accounts[idx as usize].capital.is_zero(),
            "Withdraw: negative PnL must settle immediately"
        );

        Ok(())
    }

    // ========================================
    // Trading
    // ========================================

    /// Realized-only equity: max(0, capital + realized_pnl).
    ///
    /// DEPRECATED for margin checks: Use account_equity_mtm_at_oracle instead.
    /// This helper is retained for reporting, PnL display, and test assertions that
    /// specifically need realized-only equity.
    #[inline]
    pub fn account_equity(&self, account: &Account) -> u128 {
        let cap_i = u128_to_i128_clamped(account.capital.get());
        let eq_i = cap_i.saturating_add(account.pnl.get());
        if eq_i > 0 {
            eq_i as u128
        } else {
            0
        }
    }

    /// Mark-to-market equity at oracle price with haircut (the ONLY correct equity for margin checks).
    /// equity_mtm = max(0, C_i + min(PNL_i, 0) + PNL_eff_pos_i + mark_pnl)
    /// where PNL_eff_pos_i = floor(max(PNL_i, 0) * h_num / h_den) per spec §3.3.
    ///
    /// FAIL-SAFE: On overflow, returns 0 (worst-case equity) to ensure liquidation
    /// can still trigger. This prevents overflow from blocking liquidation.
    pub fn account_equity_mtm_at_oracle(&self, account: &Account, oracle_price: u64) -> u128 {
        let mark = match Self::mark_pnl_for_position(
            account.position_size.get(),
            account.entry_price,
            oracle_price,
        ) {
            Ok(m) => m,
            Err(_) => return 0, // Overflow => worst-case equity
        };
        let cap_i = u128_to_i128_clamped(account.capital.get());
        let neg_pnl = core::cmp::min(account.pnl.get(), 0);
        let eff_pos = self.effective_pos_pnl(account.pnl.get());
        let eq_i = cap_i
            .saturating_add(neg_pnl)
            .saturating_add(u128_to_i128_clamped(eff_pos))
            .saturating_add(mark);
        let eq = if eq_i > 0 { eq_i as u128 } else { 0 };
        // Subtract fee debt (negative fee_credits = unpaid maintenance fees)
        let fee_debt = if account.fee_credits.is_negative() {
            neg_i128_to_u128(account.fee_credits.get())
        } else {
            0
        };
        eq.saturating_sub(fee_debt)
    }

    /// MTM margin check: is equity_mtm > required margin?
    /// This is the ONLY correct margin predicate for all risk checks.
    ///
    /// FAIL-SAFE: Returns false on any error (treat as below margin / liquidatable).
    pub fn is_above_margin_bps_mtm(&self, account: &Account, oracle_price: u64, bps: u64) -> bool {
        let equity = self.account_equity_mtm_at_oracle(account, oracle_price);

        // Position value at oracle price
        let position_value = mul_u128(
            saturating_abs_i128(account.position_size.get()) as u128,
            oracle_price as u128,
        ) / 1_000_000;

        // Margin requirement at given bps
        let margin_required = mul_u128(position_value, bps as u128) / 10_000;

        equity > margin_required
    }

    /// MTM maintenance margin check (fail-safe: returns false on overflow)
    #[inline]
    pub fn is_above_maintenance_margin_mtm(&self, account: &Account, oracle_price: u64) -> bool {
        self.is_above_margin_bps_mtm(account, oracle_price, self.params.maintenance_margin_bps)
    }

    /// Cheap priority score for ranking liquidation candidates.
    /// Score = max(maint_required - equity, 0).
    /// Higher score = more urgent to liquidate.
    ///
    /// This is a ranking heuristic only - NOT authoritative.
    /// Real liquidation still calls touch_account_full() and checks margin properly.
    /// A "wrong" top-K pick is harmless: it just won't liquidate.
    #[inline]
    fn liq_priority_score(&self, a: &Account, oracle_price: u64) -> u128 {
        if a.position_size.is_zero() {
            return 0;
        }

        // MTM equity (fail-safe: overflow returns 0, making account appear liquidatable)
        let equity = self.account_equity_mtm_at_oracle(a, oracle_price);

        let pos_value = mul_u128(
            saturating_abs_i128(a.position_size.get()) as u128,
            oracle_price as u128,
        ) / 1_000_000;

        let maint = mul_u128(pos_value, self.params.maintenance_margin_bps as u128) / 10_000;

        if equity >= maint {
            0
        } else {
            maint - equity
        }
    }

    /// Risk-reduction-only mode is entered when the system is in deficit. Warmups are frozen so pending PNL cannot become principal. Withdrawals of principal (capital) are allowed (subject to margin). Risk-increasing actions are blocked; only risk-reducing/neutral operations are allowed.
    /// Execute a trade between LP and user.
    /// Relies on Solana transaction atomicity: if this returns Err, the entire TX aborts.
    pub fn execute_trade<M: MatchingEngine>(
        &mut self,
        matcher: &M,
        lp_idx: u16,
        user_idx: u16,
        now_slot: u64,
        oracle_price: u64,
        size: i128,
    ) -> Result<()> {
        // Update current_slot so warmup/bookkeeping progresses consistently
        self.current_slot = now_slot;

        // Require fresh crank (time-based) before state-changing operations
        self.require_fresh_crank(now_slot)?;

        // Validate indices
        if !self.is_used(lp_idx as usize) || !self.is_used(user_idx as usize) {
            return Err(RiskError::AccountNotFound);
        }

        // Validate oracle price bounds (prevents overflow in mark_pnl calculations)
        if oracle_price == 0 || oracle_price > MAX_ORACLE_PRICE {
            return Err(RiskError::Overflow);
        }

        // Validate requested size bounds
        if size == 0 || size == i128::MIN {
            return Err(RiskError::Overflow);
        }
        if saturating_abs_i128(size) as u128 > MAX_POSITION_ABS {
            return Err(RiskError::Overflow);
        }

        // Validate account kinds (using is_lp/is_user methods for SBF workaround)
        if !self.accounts[lp_idx as usize].is_lp() {
            return Err(RiskError::AccountKindMismatch);
        }
        if !self.accounts[user_idx as usize].is_user() {
            return Err(RiskError::AccountKindMismatch);
        }

        // Check if trade increases risk (absolute exposure for either party)
        let old_user_pos = self.accounts[user_idx as usize].position_size.get();
        let old_lp_pos = self.accounts[lp_idx as usize].position_size.get();
        let new_user_pos = old_user_pos.saturating_add(size);
        let new_lp_pos = old_lp_pos.saturating_sub(size);

        let user_inc = saturating_abs_i128(new_user_pos) > saturating_abs_i128(old_user_pos);
        let lp_inc = saturating_abs_i128(new_lp_pos) > saturating_abs_i128(old_lp_pos);

        if user_inc || lp_inc {
            // Risk-increasing: require recent full sweep
            self.require_recent_full_sweep(now_slot)?;
        }

        // Call matching engine
        let lp = &self.accounts[lp_idx as usize];
        let execution = matcher.execute_match(
            &lp.matcher_program,
            &lp.matcher_context,
            lp.account_id,
            oracle_price,
            size,
        )?;

        let exec_price = execution.price;
        let exec_size = execution.size;

        // Validate matcher output (trust boundary enforcement)
        // Price bounds
        if exec_price == 0 || exec_price > MAX_ORACLE_PRICE {
            return Err(RiskError::InvalidMatchingEngine);
        }

        // Size bounds
        if exec_size == 0 {
            // No fill: treat as no-op trade (no side effects, deterministic)
            return Ok(());
        }
        if exec_size == i128::MIN {
            return Err(RiskError::InvalidMatchingEngine);
        }
        if saturating_abs_i128(exec_size) as u128 > MAX_POSITION_ABS {
            return Err(RiskError::InvalidMatchingEngine);
        }

        // Must be same direction as requested
        if (exec_size > 0) != (size > 0) {
            return Err(RiskError::InvalidMatchingEngine);
        }

        // Must be partial fill at most (abs(exec) <= abs(request))
        if saturating_abs_i128(exec_size) > saturating_abs_i128(size) {
            return Err(RiskError::InvalidMatchingEngine);
        }

        // Settle funding, mark-to-market, and maintenance fees for both accounts
        // Mark settlement MUST happen before position changes (variation margin)
        // Note: warmup is settled at the END after trade PnL is generated
        self.touch_account(user_idx)?;
        self.touch_account(lp_idx)?;

        // Per spec §5.4: if AvailGross increases from mark settlement, warmup must restart.
        // Capture old AvailGross before mark settlement for both accounts.
        let user_old_avail = {
            let pnl = self.accounts[user_idx as usize].pnl.get();
            if pnl > 0 { (pnl as u128).saturating_sub(self.accounts[user_idx as usize].reserved_pnl as u128) } else { 0 }
        };
        let lp_old_avail = {
            let pnl = self.accounts[lp_idx as usize].pnl.get();
            if pnl > 0 { (pnl as u128).saturating_sub(self.accounts[lp_idx as usize].reserved_pnl as u128) } else { 0 }
        };
        self.settle_mark_to_oracle(user_idx, oracle_price)?;
        self.settle_mark_to_oracle(lp_idx, oracle_price)?;
        // If AvailGross increased from mark settlement, update warmup slope (restarts warmup)
        let user_new_avail = {
            let pnl = self.accounts[user_idx as usize].pnl.get();
            if pnl > 0 { (pnl as u128).saturating_sub(self.accounts[user_idx as usize].reserved_pnl as u128) } else { 0 }
        };
        let lp_new_avail = {
            let pnl = self.accounts[lp_idx as usize].pnl.get();
            if pnl > 0 { (pnl as u128).saturating_sub(self.accounts[lp_idx as usize].reserved_pnl as u128) } else { 0 }
        };
        if user_new_avail > user_old_avail {
            self.update_warmup_slope(user_idx)?;
        }
        if lp_new_avail > lp_old_avail {
            self.update_warmup_slope(lp_idx)?;
        }

        self.settle_maintenance_fee(user_idx, now_slot, oracle_price)?;
        self.settle_maintenance_fee(lp_idx, now_slot, oracle_price)?;

        // Calculate fee (ceiling division to prevent micro-trade fee evasion)
        let notional =
            mul_u128(saturating_abs_i128(exec_size) as u128, exec_price as u128) / 1_000_000;
        let fee = if notional > 0 && self.params.trading_fee_bps > 0 {
            // Ceiling division: ensures at least 1 atomic unit fee for any real trade
            (mul_u128(notional, self.params.trading_fee_bps as u128) + 9999) / 10_000
        } else {
            0
        };

        // Access both accounts
        let (user, lp) = if user_idx < lp_idx {
            let (left, right) = self.accounts.split_at_mut(lp_idx as usize);
            (&mut left[user_idx as usize], &mut right[0])
        } else {
            let (left, right) = self.accounts.split_at_mut(user_idx as usize);
            (&mut right[0], &mut left[lp_idx as usize])
        };

        // Calculate new positions (checked math - overflow returns Err)
        let new_user_position = user
            .position_size
            .get()
            .checked_add(exec_size)
            .ok_or(RiskError::Overflow)?;
        let new_lp_position = lp
            .position_size
            .get()
            .checked_sub(exec_size)
            .ok_or(RiskError::Overflow)?;

        // Validate final position bounds (prevents overflow in mark_pnl calculations)
        if saturating_abs_i128(new_user_position) as u128 > MAX_POSITION_ABS
            || saturating_abs_i128(new_lp_position) as u128 > MAX_POSITION_ABS
        {
            return Err(RiskError::Overflow);
        }

        // Trade PnL = (oracle - exec_price) * exec_size (zero-sum between parties)
        // User gains if buying below oracle (exec_size > 0, oracle > exec_price)
        // LP gets opposite sign
        // Note: entry_price is already oracle_price after settle_mark_to_oracle
        let price_diff = (oracle_price as i128)
            .checked_sub(exec_price as i128)
            .ok_or(RiskError::Overflow)?;

        let trade_pnl = price_diff
            .checked_mul(exec_size)
            .ok_or(RiskError::Overflow)?
            .checked_div(1_000_000)
            .ok_or(RiskError::Overflow)?;

        // Compute final PNL values (checked math - overflow returns Err)
        let new_user_pnl = user
            .pnl
            .get()
            .checked_add(trade_pnl)
            .ok_or(RiskError::Overflow)?;
        let new_lp_pnl = lp
            .pnl
            .get()
            .checked_sub(trade_pnl)
            .ok_or(RiskError::Overflow)?;

        // Deduct trading fee from user capital, not PnL (spec §8.1)
        let new_user_capital = user
            .capital
            .get()
            .checked_sub(fee)
            .ok_or(RiskError::InsufficientBalance)?;

        // Compute projected pnl_pos_tot AFTER trade PnL for fresh haircut in margin checks.
        // Can't call self.haircut_ratio() due to split_at_mut borrow on accounts;
        // inline the delta computation and haircut formula.
        let old_user_pnl_pos = if user.pnl.get() > 0 { user.pnl.get() as u128 } else { 0 };
        let new_user_pnl_pos = if new_user_pnl > 0 { new_user_pnl as u128 } else { 0 };
        let old_lp_pnl_pos = if lp.pnl.get() > 0 { lp.pnl.get() as u128 } else { 0 };
        let new_lp_pnl_pos = if new_lp_pnl > 0 { new_lp_pnl as u128 } else { 0 };

        // Recompute haircut using projected post-trade pnl_pos_tot (spec §3.3).
        // Fee moves C→I so Residual = V - C_tot - I is unchanged; only pnl_pos_tot changes.
        let projected_pnl_pos_tot = self.pnl_pos_tot
            .get()
            .saturating_add(new_user_pnl_pos)
            .saturating_sub(old_user_pnl_pos)
            .saturating_add(new_lp_pnl_pos)
            .saturating_sub(old_lp_pnl_pos);

        let (h_num, h_den) = if projected_pnl_pos_tot == 0 {
            (1u128, 1u128)
        } else {
            let residual = self.vault.get()
                .saturating_sub(self.c_tot.get())
                .saturating_sub(self.insurance_fund.balance.get());
            (core::cmp::min(residual, projected_pnl_pos_tot), projected_pnl_pos_tot)
        };

        // Inline helper: compute effective positive PnL with post-trade haircut
        let eff_pos_pnl_inline = |pnl: i128| -> u128 {
            if pnl <= 0 {
                return 0;
            }
            let pos_pnl = pnl as u128;
            if h_den == 0 {
                return pos_pnl;
            }
            mul_u128(pos_pnl, h_num) / h_den
        };

        // Check user margin with haircut (spec §3.3, §10.4 step 7)
        // After settle_mark_to_oracle, entry_price = oracle_price, so mark_pnl = 0
        // Equity = max(0, new_capital + min(pnl, 0) + eff_pos_pnl)
        // Use initial margin if risk-increasing, maintenance margin otherwise
        if new_user_position != 0 {
            let user_cap_i = u128_to_i128_clamped(new_user_capital);
            let neg_pnl = core::cmp::min(new_user_pnl, 0);
            let eff_pos = eff_pos_pnl_inline(new_user_pnl);
            let user_eq_i = user_cap_i
                .saturating_add(neg_pnl)
                .saturating_add(u128_to_i128_clamped(eff_pos));
            let user_equity = if user_eq_i > 0 { user_eq_i as u128 } else { 0 };
            // Subtract fee debt (negative fee_credits = unpaid maintenance fees)
            let user_fee_debt = if user.fee_credits.is_negative() {
                neg_i128_to_u128(user.fee_credits.get())
            } else {
                0
            };
            let user_equity = user_equity.saturating_sub(user_fee_debt);
            let position_value = mul_u128(
                saturating_abs_i128(new_user_position) as u128,
                oracle_price as u128,
            ) / 1_000_000;
            // Risk-increasing if |new_pos| > |old_pos| OR position crosses zero (flip)
            // A flip is semantically a close + open, so the new side must meet initial margin
            let old_user_pos = user.position_size.get();
            let old_user_pos_abs = saturating_abs_i128(old_user_pos);
            let new_user_pos_abs = saturating_abs_i128(new_user_position);
            let user_crosses_zero =
                (old_user_pos > 0 && new_user_position < 0) || (old_user_pos < 0 && new_user_position > 0);
            let user_risk_increasing = new_user_pos_abs > old_user_pos_abs || user_crosses_zero;
            let margin_bps = if user_risk_increasing {
                self.params.initial_margin_bps
            } else {
                self.params.maintenance_margin_bps
            };
            let margin_required = mul_u128(position_value, margin_bps as u128) / 10_000;
            if user_equity <= margin_required {
                return Err(RiskError::Undercollateralized);
            }
        }

        // Check LP margin with haircut (spec §3.3, §10.4 step 7)
        // After settle_mark_to_oracle, entry_price = oracle_price, so mark_pnl = 0
        // Use initial margin if risk-increasing, maintenance margin otherwise
        if new_lp_position != 0 {
            let lp_cap_i = u128_to_i128_clamped(lp.capital.get());
            let neg_pnl = core::cmp::min(new_lp_pnl, 0);
            let eff_pos = eff_pos_pnl_inline(new_lp_pnl);
            let lp_eq_i = lp_cap_i
                .saturating_add(neg_pnl)
                .saturating_add(u128_to_i128_clamped(eff_pos));
            let lp_equity = if lp_eq_i > 0 { lp_eq_i as u128 } else { 0 };
            // Subtract fee debt (negative fee_credits = unpaid maintenance fees)
            let lp_fee_debt = if lp.fee_credits.is_negative() {
                neg_i128_to_u128(lp.fee_credits.get())
            } else {
                0
            };
            let lp_equity = lp_equity.saturating_sub(lp_fee_debt);
            let position_value = mul_u128(
                saturating_abs_i128(new_lp_position) as u128,
                oracle_price as u128,
            ) / 1_000_000;
            // Risk-increasing if |new_pos| > |old_pos| OR position crosses zero (flip)
            // A flip is semantically a close + open, so the new side must meet initial margin
            let old_lp_pos = lp.position_size.get();
            let old_lp_pos_abs = saturating_abs_i128(old_lp_pos);
            let new_lp_pos_abs = saturating_abs_i128(new_lp_position);
            let lp_crosses_zero =
                (old_lp_pos > 0 && new_lp_position < 0) || (old_lp_pos < 0 && new_lp_position > 0);
            let lp_risk_increasing = new_lp_pos_abs > old_lp_pos_abs || lp_crosses_zero;
            let margin_bps = if lp_risk_increasing {
                self.params.initial_margin_bps
            } else {
                self.params.maintenance_margin_bps
            };
            let margin_required = mul_u128(position_value, margin_bps as u128) / 10_000;
            if lp_equity <= margin_required {
                return Err(RiskError::Undercollateralized);
            }
        }

        // Commit all state changes
        self.insurance_fund.fee_revenue =
            U128::new(add_u128(self.insurance_fund.fee_revenue.get(), fee));
        self.insurance_fund.balance = U128::new(add_u128(self.insurance_fund.balance.get(), fee));

        // Credit fee to user's fee_credits (active traders earn credits that offset maintenance)
        user.fee_credits = user.fee_credits.saturating_add(fee as i128);

        // §4.3 Batch update exception: Direct field assignment for performance.
        // All aggregate deltas (old/new pnl_pos values) computed above before assignment;
        // aggregates (c_tot, pnl_pos_tot) updated atomically below.
        user.pnl = I128::new(new_user_pnl);
        user.position_size = I128::new(new_user_position);
        user.entry_price = oracle_price;
        // Commit fee deduction from user capital (spec §8.1)
        user.capital = U128::new(new_user_capital);

        lp.pnl = I128::new(new_lp_pnl);
        lp.position_size = I128::new(new_lp_position);
        lp.entry_price = oracle_price;

        // §4.1, §4.2: Atomic aggregate maintenance after batch field assignments
        // Maintain c_tot: user capital decreased by fee
        self.c_tot = U128::new(self.c_tot.get().saturating_sub(fee));

        // Maintain pnl_pos_tot aggregate
        self.pnl_pos_tot = U128::new(
            self.pnl_pos_tot
                .get()
                .saturating_add(new_user_pnl_pos)
                .saturating_sub(old_user_pnl_pos)
                .saturating_add(new_lp_pnl_pos)
                .saturating_sub(old_lp_pnl_pos),
        );

        // Update total open interest tracking (O(1))
        // OI = sum of abs(position_size) across all accounts
        let old_oi =
            saturating_abs_i128(old_user_pos) as u128 + saturating_abs_i128(old_lp_pos) as u128;
        let new_oi = saturating_abs_i128(new_user_position) as u128
            + saturating_abs_i128(new_lp_position) as u128;
        if new_oi > old_oi {
            self.total_open_interest = self.total_open_interest.saturating_add(new_oi - old_oi);
        } else {
            self.total_open_interest = self.total_open_interest.saturating_sub(old_oi - new_oi);
        }

        // Update LP aggregates for funding/threshold (O(1))
        let old_lp_abs = saturating_abs_i128(old_lp_pos) as u128;
        let new_lp_abs = saturating_abs_i128(new_lp_position) as u128;
        // net_lp_pos: delta = new - old
        self.net_lp_pos = self
            .net_lp_pos
            .saturating_sub(old_lp_pos)
            .saturating_add(new_lp_position);
        // lp_sum_abs: delta of abs values
        if new_lp_abs > old_lp_abs {
            self.lp_sum_abs = self.lp_sum_abs.saturating_add(new_lp_abs - old_lp_abs);
        } else {
            self.lp_sum_abs = self.lp_sum_abs.saturating_sub(old_lp_abs - new_lp_abs);
        }
        // lp_max_abs: monotone increase only (conservative upper bound)
        self.lp_max_abs = U128::new(self.lp_max_abs.get().max(new_lp_abs));

        // Two-pass settlement: losses first, then profits.
        // This ensures the loser's capital reduction increases Residual before
        // the winner's profit conversion reads the haircut ratio. Without this,
        // the winner's matured PnL can be haircutted to 0 because Residual
        // hasn't been increased by the loser's loss settlement yet (Finding G).
        self.settle_loss_only(user_idx)?;
        self.settle_loss_only(lp_idx)?;
        // Now Residual reflects realized losses; profit conversion uses correct h.
        self.settle_warmup_to_capital(user_idx)?;
        self.settle_warmup_to_capital(lp_idx)?;

        // Now recompute warmup slopes after PnL changes (resets started_at_slot)
        self.update_warmup_slope(user_idx)?;
        self.update_warmup_slope(lp_idx)?;

        Ok(())
    }
    /// Settle loss only (§6.1): negative PnL pays from capital immediately.
    /// If PnL still negative after capital exhausted, write off via set_pnl(i, 0).
    /// Used in two-pass settlement to ensure all losses are realized (increasing
    /// Residual) before any profit conversions use the haircut ratio.
    pub fn settle_loss_only(&mut self, idx: u16) -> Result<()> {
        if !self.is_used(idx as usize) {
            return Err(RiskError::AccountNotFound);
        }

        let pnl = self.accounts[idx as usize].pnl.get();
        if pnl < 0 {
            let need = neg_i128_to_u128(pnl);
            let capital = self.accounts[idx as usize].capital.get();
            let pay = core::cmp::min(need, capital);

            if pay > 0 {
                self.set_capital(idx as usize, capital - pay);
                self.set_pnl(idx as usize, pnl.saturating_add(pay as i128));
            }

            // Write off any remaining negative PnL (spec §6.1 step 4)
            if self.accounts[idx as usize].pnl.is_negative() {
                self.set_pnl(idx as usize, 0);
            }
        }

        Ok(())
    }

    /// Settle warmup: loss settlement + profit conversion per spec §6
    ///
    /// §6.1 Loss settlement: negative PnL pays from capital immediately.
    ///   If PnL still negative after capital exhausted, write off via set_pnl(i, 0).
    ///
    /// §6.2 Profit conversion: warmable gross profit converts to capital at haircut ratio h.
    ///   y = floor(x * h_num / h_den), where (h_num, h_den) is computed pre-conversion.
    pub fn settle_warmup_to_capital(&mut self, idx: u16) -> Result<()> {
        if !self.is_used(idx as usize) {
            return Err(RiskError::AccountNotFound);
        }

        // §6.1 Loss settlement (negative PnL → reduce capital immediately)
        let pnl = self.accounts[idx as usize].pnl.get();
        if pnl < 0 {
            let need = neg_i128_to_u128(pnl);
            let capital = self.accounts[idx as usize].capital.get();
            let pay = core::cmp::min(need, capital);

            if pay > 0 {
                self.set_capital(idx as usize, capital - pay);
                self.set_pnl(idx as usize, pnl.saturating_add(pay as i128));
            }

            // Write off any remaining negative PnL (spec §6.1 step 4)
            if self.accounts[idx as usize].pnl.is_negative() {
                self.set_pnl(idx as usize, 0);
            }
        }

        // §6.2 Profit conversion (warmup converts junior profit → protected principal)
        let pnl = self.accounts[idx as usize].pnl.get();
        if pnl > 0 {
            let positive_pnl = pnl as u128;
            let reserved = self.accounts[idx as usize].reserved_pnl as u128;
            let avail_gross = positive_pnl.saturating_sub(reserved);

            // Compute warmable cap from slope and elapsed time (spec §5.3)
            let started_at = self.accounts[idx as usize].warmup_started_at_slot;
            let elapsed = self.current_slot.saturating_sub(started_at);
            let slope = self.accounts[idx as usize].warmup_slope_per_step.get();
            let cap = mul_u128(slope, elapsed as u128);

            let x = core::cmp::min(avail_gross, cap);

            if x > 0 {
                // Compute haircut ratio BEFORE modifying PnL/capital (spec §6.2)
                let (h_num, h_den) = self.haircut_ratio();
                let y = if h_den == 0 {
                    x
                } else {
                    mul_u128(x, h_num) / h_den
                };

                // Reduce junior profit claim by x
                self.set_pnl(idx as usize, pnl - (x as i128));
                // Increase protected principal by y
                let new_cap = add_u128(self.accounts[idx as usize].capital.get(), y);
                self.set_capital(idx as usize, new_cap);
            }

            // Advance warmup time base and update slope (spec §5.4)
            self.accounts[idx as usize].warmup_started_at_slot = self.current_slot;

            // Recompute warmup slope per spec §5.4
            let new_pnl = self.accounts[idx as usize].pnl.get();
            let new_avail = if new_pnl > 0 {
                (new_pnl as u128).saturating_sub(self.accounts[idx as usize].reserved_pnl as u128)
            } else {
                0
            };
            let slope = if new_avail == 0 {
                0
            } else if self.params.warmup_period_slots > 0 {
                core::cmp::max(1, new_avail / (self.params.warmup_period_slots as u128))
            } else {
                new_avail
            };
            self.accounts[idx as usize].warmup_slope_per_step = U128::new(slope);
        }

        Ok(())
    }

    // Panic Settlement (Atomic Global Settle)
    // ========================================

    /// Top up insurance fund
    ///
    /// Adds tokens to both vault and insurance fund.
    /// Returns true if the top-up brings insurance above the risk reduction threshold.
    pub fn top_up_insurance_fund(&mut self, amount: u128) -> Result<bool> {
        // Add to vault
        self.vault = U128::new(add_u128(self.vault.get(), amount));

        // Add to insurance fund
        self.insurance_fund.balance =
            U128::new(add_u128(self.insurance_fund.balance.get(), amount));

        // Return whether we're now above the force-realize threshold
        let above_threshold =
            self.insurance_fund.balance > self.params.risk_reduction_threshold;
        Ok(above_threshold)
    }


    // ========================================
    // Utilities
    // ========================================

    /// Check conservation invariant (spec §3.1)
    ///
    /// Primary invariant: V >= C_tot + I
    ///
    /// Extended check: vault >= sum(capital) + sum(positive_pnl_clamped) + insurance
    /// with bounded rounding slack from funding/mark settlement.
    ///
    /// We also verify the full accounting identity including settled/unsettled PnL:
    /// vault >= sum(capital) + sum(settled_pnl + mark_pnl) + insurance
    /// The difference (slack) must be bounded by MAX_ROUNDING_SLACK.
    pub fn check_conservation(&self, oracle_price: u64) -> bool {
        let mut total_capital = 0u128;
        let mut net_pnl: i128 = 0;
        let mut net_mark: i128 = 0;
        let mut mark_ok = true;
        let global_index = self.funding_index_qpb_e6;

        self.for_each_used(|_idx, account| {
            total_capital = add_u128(total_capital, account.capital.get());

            // Compute "would-be settled" PNL for this account
            let mut settled_pnl = account.pnl.get();
            if !account.position_size.is_zero() {
                let delta_f = global_index
                    .get()
                    .saturating_sub(account.funding_index.get());
                if delta_f != 0 {
                    let raw = account.position_size.get().saturating_mul(delta_f);
                    let payment = if raw > 0 {
                        raw.saturating_add(999_999).saturating_div(1_000_000)
                    } else {
                        raw.saturating_div(1_000_000)
                    };
                    settled_pnl = settled_pnl.saturating_sub(payment);
                }

                match Self::mark_pnl_for_position(
                    account.position_size.get(),
                    account.entry_price,
                    oracle_price,
                ) {
                    Ok(mark) => {
                        net_mark = net_mark.saturating_add(mark);
                    }
                    Err(_) => {
                        mark_ok = false;
                    }
                }
            }
            net_pnl = net_pnl.saturating_add(settled_pnl);
        });

        if !mark_ok {
            return false;
        }

        // Conservation: vault >= C_tot + I (primary invariant)
        let primary = self.vault.get()
            >= total_capital.saturating_add(self.insurance_fund.balance.get());
        if !primary {
            return false;
        }

        // Extended: vault >= sum(capital) + sum(settled_pnl + mark_pnl) + insurance
        let total_pnl = net_pnl.saturating_add(net_mark);
        let base = add_u128(total_capital, self.insurance_fund.balance.get());

        let expected = if total_pnl >= 0 {
            add_u128(base, total_pnl as u128)
        } else {
            base.saturating_sub(neg_i128_to_u128(total_pnl))
        };

        let actual = self.vault.get();

        if actual < expected {
            return false;
        }
        let slack = actual - expected;
        slack <= MAX_ROUNDING_SLACK
    }

    /// Advance to next slot (for testing warmup)
    pub fn advance_slot(&mut self, slots: u64) {
        self.current_slot = self.current_slot.saturating_add(slots);
    }
}

pub mod i128 {
// ============================================================================
// BPF-Safe 128-bit Types
// ============================================================================
//
}
// CRITICAL: Rust 1.77/1.78 changed i128/u128 alignment from 8 to 16 bytes on x86_64,
// but BPF/SBF still uses 8-byte alignment. This causes struct layout mismatches
// when reading/writing 128-bit values on-chain.
//
// These wrapper types use [u64; 2] internally to ensure consistent 8-byte alignment
// across all platforms. See: https://blog.rust-lang.org/2024/03/30/i128-layout-update.html
//
// KANI OPTIMIZATION: For Kani builds, we use transparent newtypes around raw
// primitives. This dramatically reduces SAT solver complexity since Kani doesn't
// have to reason about bit-shifting and array indexing for every 128-bit operation.

// ============================================================================
// I128 - Kani-optimized version (transparent newtype)
// ============================================================================
#[cfg(kani)]
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct I128(i128);

#[cfg(kani)]
impl I128 {
    pub const ZERO: Self = Self(0);
    pub const MIN: Self = Self(i128::MIN);
    pub const MAX: Self = Self(i128::MAX);

    #[inline(always)]
    pub const fn new(val: i128) -> Self {
        Self(val)
    }

    #[inline(always)]
    pub const fn get(self) -> i128 {
        self.0
    }

    #[inline(always)]
    pub fn set(&mut self, val: i128) {
        self.0 = val;
    }

    #[inline(always)]
    pub fn checked_add(self, rhs: i128) -> Option<Self> {
        self.0.checked_add(rhs).map(Self)
    }

    #[inline(always)]
    pub fn checked_sub(self, rhs: i128) -> Option<Self> {
        self.0.checked_sub(rhs).map(Self)
    }

    #[inline(always)]
    pub fn checked_mul(self, rhs: i128) -> Option<Self> {
        self.0.checked_mul(rhs).map(Self)
    }

    #[inline(always)]
    pub fn checked_div(self, rhs: i128) -> Option<Self> {
        self.0.checked_div(rhs).map(Self)
    }

    #[inline(always)]
    pub fn saturating_add(self, rhs: i128) -> Self {
        Self(self.0.saturating_add(rhs))
    }

    #[inline(always)]
    pub fn saturating_add_i128(self, rhs: I128) -> Self {
        Self(self.0.saturating_add(rhs.0))
    }

    #[inline(always)]
    pub fn saturating_sub(self, rhs: i128) -> Self {
        Self(self.0.saturating_sub(rhs))
    }

    #[inline(always)]
    pub fn saturating_sub_i128(self, rhs: I128) -> Self {
        Self(self.0.saturating_sub(rhs.0))
    }

    #[inline(always)]
    pub fn wrapping_add(self, rhs: i128) -> Self {
        Self(self.0.wrapping_add(rhs))
    }

    #[inline(always)]
    pub fn abs(self) -> Self {
        Self(self.0.abs())
    }

    #[inline(always)]
    pub fn unsigned_abs(self) -> u128 {
        self.0.unsigned_abs()
    }

    #[inline(always)]
    pub fn is_zero(self) -> bool {
        self.0 == 0
    }

    #[inline(always)]
    pub fn is_negative(self) -> bool {
        self.0 < 0
    }

    #[inline(always)]
    pub fn is_positive(self) -> bool {
        self.0 > 0
    }
}

// ============================================================================
// I128 - BPF version (array-based for alignment)
// ============================================================================
/// BPF-safe signed 128-bit integer using [u64; 2] for consistent alignment.
/// Layout: [lo, hi] in little-endian order.
// Kani I128 trait implementations
#[cfg(kani)]
impl Default for I128 {
    fn default() -> Self {
        Self::ZERO
    }
}

#[cfg(kani)]
impl core::fmt::Debug for I128 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "I128({})", self.0)
    }
}

#[cfg(kani)]
impl core::fmt::Display for I128 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(kani)]
impl From<i128> for I128 {
    fn from(val: i128) -> Self {
        Self(val)
    }
}

#[cfg(kani)]
impl From<i64> for I128 {
    fn from(val: i64) -> Self {
        Self(val as i128)
    }
}

#[cfg(kani)]
impl From<I128> for i128 {
    fn from(val: I128) -> Self {
        val.0
    }
}

#[cfg(kani)]
impl PartialOrd for I128 {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(kani)]
impl Ord for I128 {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

#[cfg(kani)]
impl core::ops::Add<i128> for I128 {
    type Output = Self;
    fn add(self, rhs: i128) -> Self {
        Self(self.0.saturating_add(rhs))
    }
}

#[cfg(kani)]
impl core::ops::Add<I128> for I128 {
    type Output = Self;
    fn add(self, rhs: I128) -> Self {
        Self(self.0.saturating_add(rhs.0))
    }
}

#[cfg(kani)]
impl core::ops::Sub<i128> for I128 {
    type Output = Self;
    fn sub(self, rhs: i128) -> Self {
        Self(self.0.saturating_sub(rhs))
    }
}

#[cfg(kani)]
impl core::ops::Sub<I128> for I128 {
    type Output = Self;
    fn sub(self, rhs: I128) -> Self {
        Self(self.0.saturating_sub(rhs.0))
    }
}

#[cfg(kani)]
impl core::ops::Neg for I128 {
    type Output = Self;
    fn neg(self) -> Self {
        Self(self.0.saturating_neg())
    }
}

#[cfg(kani)]
impl core::ops::AddAssign<i128> for I128 {
    fn add_assign(&mut self, rhs: i128) {
        *self = *self + rhs;
    }
}

#[cfg(kani)]
impl core::ops::SubAssign<i128> for I128 {
    fn sub_assign(&mut self, rhs: i128) {
        *self = *self - rhs;
    }
}

// ============================================================================
// I128 - BPF version (array-based for alignment)
// ============================================================================
#[cfg(not(kani))]
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct I128([u64; 2]);

#[cfg(not(kani))]
impl I128 {
    pub const ZERO: Self = Self([0, 0]);
    pub const MIN: Self = Self([0, 0x8000_0000_0000_0000]); // i128::MIN
    pub const MAX: Self = Self([u64::MAX, 0x7FFF_FFFF_FFFF_FFFF]); // i128::MAX

    #[inline]
    pub const fn new(val: i128) -> Self {
        Self([val as u64, (val >> 64) as u64])
    }

    #[inline]
    pub const fn get(self) -> i128 {
        // Sign-extend: treat hi as signed
        ((self.0[1] as i128) << 64) | (self.0[0] as u128 as i128)
    }

    #[inline]
    pub fn set(&mut self, val: i128) {
        self.0[0] = val as u64;
        self.0[1] = (val >> 64) as u64;
    }

    #[inline]
    pub fn checked_add(self, rhs: i128) -> Option<Self> {
        self.get().checked_add(rhs).map(Self::new)
    }

    #[inline]
    pub fn checked_sub(self, rhs: i128) -> Option<Self> {
        self.get().checked_sub(rhs).map(Self::new)
    }

    #[inline]
    pub fn checked_mul(self, rhs: i128) -> Option<Self> {
        self.get().checked_mul(rhs).map(Self::new)
    }

    #[inline]
    pub fn checked_div(self, rhs: i128) -> Option<Self> {
        self.get().checked_div(rhs).map(Self::new)
    }

    #[inline]
    pub fn saturating_add(self, rhs: i128) -> Self {
        Self::new(self.get().saturating_add(rhs))
    }

    #[inline]
    pub fn saturating_add_i128(self, rhs: I128) -> Self {
        Self::new(self.get().saturating_add(rhs.get()))
    }

    #[inline]
    pub fn saturating_sub(self, rhs: i128) -> Self {
        Self::new(self.get().saturating_sub(rhs))
    }

    #[inline]
    pub fn saturating_sub_i128(self, rhs: I128) -> Self {
        Self::new(self.get().saturating_sub(rhs.get()))
    }

    #[inline]
    pub fn wrapping_add(self, rhs: i128) -> Self {
        Self::new(self.get().wrapping_add(rhs))
    }

    #[inline]
    pub fn abs(self) -> Self {
        Self::new(self.get().abs())
    }

    #[inline]
    pub fn unsigned_abs(self) -> u128 {
        self.get().unsigned_abs()
    }

    #[inline]
    pub fn is_zero(self) -> bool {
        self.0[0] == 0 && self.0[1] == 0
    }

    #[inline]
    pub fn is_negative(self) -> bool {
        (self.0[1] as i64) < 0
    }

    #[inline]
    pub fn is_positive(self) -> bool {
        !self.is_zero() && !self.is_negative()
    }
}

#[cfg(not(kani))]
impl Default for I128 {
    fn default() -> Self {
        Self::ZERO
    }
}

#[cfg(not(kani))]
impl core::fmt::Debug for I128 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "I128({})", self.get())
    }
}

#[cfg(not(kani))]
impl core::fmt::Display for I128 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.get())
    }
}

#[cfg(not(kani))]
impl From<i128> for I128 {
    fn from(val: i128) -> Self {
        Self::new(val)
    }
}

#[cfg(not(kani))]
impl From<i64> for I128 {
    fn from(val: i64) -> Self {
        Self::new(val as i128)
    }
}

#[cfg(not(kani))]
impl From<I128> for i128 {
    fn from(val: I128) -> Self {
        val.get()
    }
}

#[cfg(not(kani))]
impl PartialOrd for I128 {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(not(kani))]
impl Ord for I128 {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.get().cmp(&other.get())
    }
}

// ============================================================================
// U128 - Kani-optimized version (transparent newtype)
// ============================================================================
#[cfg(kani)]
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct U128(u128);

#[cfg(kani)]
impl U128 {
    pub const ZERO: Self = Self(0);
    pub const MAX: Self = Self(u128::MAX);

    #[inline(always)]
    pub const fn new(val: u128) -> Self {
        Self(val)
    }

    #[inline(always)]
    pub const fn get(self) -> u128 {
        self.0
    }

    #[inline(always)]
    pub fn set(&mut self, val: u128) {
        self.0 = val;
    }

    #[inline(always)]
    pub fn checked_add(self, rhs: u128) -> Option<Self> {
        self.0.checked_add(rhs).map(Self)
    }

    #[inline(always)]
    pub fn checked_sub(self, rhs: u128) -> Option<Self> {
        self.0.checked_sub(rhs).map(Self)
    }

    #[inline(always)]
    pub fn checked_mul(self, rhs: u128) -> Option<Self> {
        self.0.checked_mul(rhs).map(Self)
    }

    #[inline(always)]
    pub fn checked_div(self, rhs: u128) -> Option<Self> {
        self.0.checked_div(rhs).map(Self)
    }

    #[inline(always)]
    pub fn saturating_add(self, rhs: u128) -> Self {
        Self(self.0.saturating_add(rhs))
    }

    #[inline(always)]
    pub fn saturating_add_u128(self, rhs: U128) -> Self {
        Self(self.0.saturating_add(rhs.0))
    }

    #[inline(always)]
    pub fn saturating_sub(self, rhs: u128) -> Self {
        Self(self.0.saturating_sub(rhs))
    }

    #[inline(always)]
    pub fn saturating_sub_u128(self, rhs: U128) -> Self {
        Self(self.0.saturating_sub(rhs.0))
    }

    #[inline(always)]
    pub fn saturating_mul(self, rhs: u128) -> Self {
        Self(self.0.saturating_mul(rhs))
    }

    #[inline(always)]
    pub fn wrapping_add(self, rhs: u128) -> Self {
        Self(self.0.wrapping_add(rhs))
    }

    #[inline(always)]
    pub fn max(self, rhs: Self) -> Self {
        if self.0 >= rhs.0 {
            self
        } else {
            rhs
        }
    }

    #[inline(always)]
    pub fn min(self, rhs: Self) -> Self {
        if self.0 <= rhs.0 {
            self
        } else {
            rhs
        }
    }

    #[inline(always)]
    pub fn is_zero(self) -> bool {
        self.0 == 0
    }
}

#[cfg(kani)]
impl Default for U128 {
    fn default() -> Self {
        Self::ZERO
    }
}

#[cfg(kani)]
impl core::fmt::Debug for U128 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "U128({})", self.0)
    }
}

#[cfg(kani)]
impl core::fmt::Display for U128 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(kani)]
impl From<u128> for U128 {
    fn from(val: u128) -> Self {
        Self(val)
    }
}

#[cfg(kani)]
impl From<u64> for U128 {
    fn from(val: u64) -> Self {
        Self(val as u128)
    }
}

#[cfg(kani)]
impl From<U128> for u128 {
    fn from(val: U128) -> Self {
        val.0
    }
}

#[cfg(kani)]
impl PartialOrd for U128 {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(kani)]
impl Ord for U128 {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

#[cfg(kani)]
impl core::ops::Add<u128> for U128 {
    type Output = Self;
    fn add(self, rhs: u128) -> Self {
        Self(self.0.saturating_add(rhs))
    }
}

#[cfg(kani)]
impl core::ops::Add<U128> for U128 {
    type Output = Self;
    fn add(self, rhs: U128) -> Self {
        Self(self.0.saturating_add(rhs.0))
    }
}

#[cfg(kani)]
impl core::ops::Sub<u128> for U128 {
    type Output = Self;
    fn sub(self, rhs: u128) -> Self {
        Self(self.0.saturating_sub(rhs))
    }
}

#[cfg(kani)]
impl core::ops::Sub<U128> for U128 {
    type Output = Self;
    fn sub(self, rhs: U128) -> Self {
        Self(self.0.saturating_sub(rhs.0))
    }
}

#[cfg(kani)]
impl core::ops::Mul<u128> for U128 {
    type Output = Self;
    fn mul(self, rhs: u128) -> Self {
        Self(self.0.saturating_mul(rhs))
    }
}

#[cfg(kani)]
impl core::ops::Mul<U128> for U128 {
    type Output = Self;
    fn mul(self, rhs: U128) -> Self {
        Self(self.0.saturating_mul(rhs.0))
    }
}

#[cfg(kani)]
impl core::ops::Div<u128> for U128 {
    type Output = Self;
    fn div(self, rhs: u128) -> Self {
        Self(self.0 / rhs)
    }
}

#[cfg(kani)]
impl core::ops::Div<U128> for U128 {
    type Output = Self;
    fn div(self, rhs: U128) -> Self {
        Self(self.0 / rhs.0)
    }
}

#[cfg(kani)]
impl core::ops::AddAssign<u128> for U128 {
    fn add_assign(&mut self, rhs: u128) {
        *self = *self + rhs;
    }
}

#[cfg(kani)]
impl core::ops::SubAssign<u128> for U128 {
    fn sub_assign(&mut self, rhs: u128) {
        *self = *self - rhs;
    }
}

// ============================================================================
// U128 - BPF version (array-based for alignment)
// ============================================================================
/// BPF-safe unsigned 128-bit integer using [u64; 2] for consistent alignment.
/// Layout: [lo, hi] in little-endian order.
#[cfg(not(kani))]
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct U128([u64; 2]);

#[cfg(not(kani))]
impl U128 {
    pub const ZERO: Self = Self([0, 0]);
    pub const MAX: Self = Self([u64::MAX, u64::MAX]);

    #[inline]
    pub const fn new(val: u128) -> Self {
        Self([val as u64, (val >> 64) as u64])
    }

    #[inline]
    pub const fn get(self) -> u128 {
        ((self.0[1] as u128) << 64) | (self.0[0] as u128)
    }

    #[inline]
    pub fn set(&mut self, val: u128) {
        self.0[0] = val as u64;
        self.0[1] = (val >> 64) as u64;
    }

    #[inline]
    pub fn checked_add(self, rhs: u128) -> Option<Self> {
        self.get().checked_add(rhs).map(Self::new)
    }

    #[inline]
    pub fn checked_sub(self, rhs: u128) -> Option<Self> {
        self.get().checked_sub(rhs).map(Self::new)
    }

    #[inline]
    pub fn checked_mul(self, rhs: u128) -> Option<Self> {
        self.get().checked_mul(rhs).map(Self::new)
    }

    #[inline]
    pub fn checked_div(self, rhs: u128) -> Option<Self> {
        self.get().checked_div(rhs).map(Self::new)
    }

    #[inline]
    pub fn saturating_add(self, rhs: u128) -> Self {
        Self::new(self.get().saturating_add(rhs))
    }

    #[inline]
    pub fn saturating_add_u128(self, rhs: U128) -> Self {
        Self::new(self.get().saturating_add(rhs.get()))
    }

    #[inline]
    pub fn saturating_sub(self, rhs: u128) -> Self {
        Self::new(self.get().saturating_sub(rhs))
    }

    #[inline]
    pub fn saturating_sub_u128(self, rhs: U128) -> Self {
        Self::new(self.get().saturating_sub(rhs.get()))
    }

    #[inline]
    pub fn saturating_mul(self, rhs: u128) -> Self {
        Self::new(self.get().saturating_mul(rhs))
    }

    #[inline]
    pub fn wrapping_add(self, rhs: u128) -> Self {
        Self::new(self.get().wrapping_add(rhs))
    }

    #[inline]
    pub fn max(self, rhs: Self) -> Self {
        if self.get() >= rhs.get() {
            self
        } else {
            rhs
        }
    }

    #[inline]
    pub fn min(self, rhs: Self) -> Self {
        if self.get() <= rhs.get() {
            self
        } else {
            rhs
        }
    }

    #[inline]
    pub fn is_zero(self) -> bool {
        self.0[0] == 0 && self.0[1] == 0
    }
}

#[cfg(not(kani))]
impl Default for U128 {
    fn default() -> Self {
        Self::ZERO
    }
}

#[cfg(not(kani))]
impl core::fmt::Debug for U128 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "U128({})", self.get())
    }
}

#[cfg(not(kani))]
impl core::fmt::Display for U128 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.get())
    }
}

#[cfg(not(kani))]
impl From<u128> for U128 {
    fn from(val: u128) -> Self {
        Self::new(val)
    }
}

#[cfg(not(kani))]
impl From<u64> for U128 {
    fn from(val: u64) -> Self {
        Self::new(val as u128)
    }
}

#[cfg(not(kani))]
impl From<U128> for u128 {
    fn from(val: U128) -> Self {
        val.get()
    }
}

#[cfg(not(kani))]
impl PartialOrd for U128 {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(not(kani))]
impl Ord for U128 {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.get().cmp(&other.get())
    }
}

// Arithmetic operators for U128 (BPF version)
#[cfg(not(kani))]
impl core::ops::Add<u128> for U128 {
    type Output = Self;
    fn add(self, rhs: u128) -> Self {
        Self::new(self.get().saturating_add(rhs))
    }
}

#[cfg(not(kani))]
impl core::ops::Add<U128> for U128 {
    type Output = Self;
    fn add(self, rhs: U128) -> Self {
        Self::new(self.get().saturating_add(rhs.get()))
    }
}

#[cfg(not(kani))]
impl core::ops::Sub<u128> for U128 {
    type Output = Self;
    fn sub(self, rhs: u128) -> Self {
        Self::new(self.get().saturating_sub(rhs))
    }
}

#[cfg(not(kani))]
impl core::ops::Sub<U128> for U128 {
    type Output = Self;
    fn sub(self, rhs: U128) -> Self {
        Self::new(self.get().saturating_sub(rhs.get()))
    }
}

#[cfg(not(kani))]
impl core::ops::Mul<u128> for U128 {
    type Output = Self;
    fn mul(self, rhs: u128) -> Self {
        Self::new(self.get().saturating_mul(rhs))
    }
}

#[cfg(not(kani))]
impl core::ops::Mul<U128> for U128 {
    type Output = Self;
    fn mul(self, rhs: U128) -> Self {
        Self::new(self.get().saturating_mul(rhs.get()))
    }
}

#[cfg(not(kani))]
impl core::ops::Div<u128> for U128 {
    type Output = Self;
    fn div(self, rhs: u128) -> Self {
        Self::new(self.get() / rhs)
    }
}

#[cfg(not(kani))]
impl core::ops::Div<U128> for U128 {
    type Output = Self;
    fn div(self, rhs: U128) -> Self {
        Self::new(self.get() / rhs.get())
    }
}

#[cfg(not(kani))]
impl core::ops::AddAssign<u128> for U128 {
    fn add_assign(&mut self, rhs: u128) {
        *self = *self + rhs;
    }
}

#[cfg(not(kani))]
impl core::ops::SubAssign<u128> for U128 {
    fn sub_assign(&mut self, rhs: u128) {
        *self = *self - rhs;
    }
}

// Arithmetic operators for I128 (BPF version)
#[cfg(not(kani))]
impl core::ops::Add<i128> for I128 {
    type Output = Self;
    fn add(self, rhs: i128) -> Self {
        Self::new(self.get().saturating_add(rhs))
    }
}

#[cfg(not(kani))]
impl core::ops::Add<I128> for I128 {
    type Output = Self;
    fn add(self, rhs: I128) -> Self {
        Self::new(self.get().saturating_add(rhs.get()))
    }
}

#[cfg(not(kani))]
impl core::ops::Sub<i128> for I128 {
    type Output = Self;
    fn sub(self, rhs: i128) -> Self {
        Self::new(self.get().saturating_sub(rhs))
    }
}

#[cfg(not(kani))]
impl core::ops::Sub<I128> for I128 {
    type Output = Self;
    fn sub(self, rhs: I128) -> Self {
        Self::new(self.get().saturating_sub(rhs.get()))
    }
}

#[cfg(not(kani))]
impl core::ops::Mul<i128> for I128 {
    type Output = Self;
    fn mul(self, rhs: i128) -> Self {
        Self::new(self.get().saturating_mul(rhs))
    }
}

#[cfg(not(kani))]
impl core::ops::Neg for I128 {
    type Output = Self;
    fn neg(self) -> Self {
        Self::new(-self.get())
    }
}

#[cfg(not(kani))]
impl core::ops::AddAssign<i128> for I128 {
    fn add_assign(&mut self, rhs: i128) {
        *self = *self + rhs;
    }
}

#[cfg(not(kani))]
impl core::ops::SubAssign<i128> for I128 {
    fn sub_assign(&mut self, rhs: i128) {
        *self = *self - rhs;
    }
}
}
pub mod percolator { pub use crate::percolator_core::*; pub use crate::i128::*; } pub mod risk { pub use crate::percolator::*; }

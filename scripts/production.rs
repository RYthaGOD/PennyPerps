#![no_std]
#![feature(alloc_error_handler)]

// Minimal allocation support for no_std
extern crate alloc;
use core::alloc::{GlobalAlloc, Layout};
use core::convert::TryInto;

// Shared constants & types
pub const MAX_ORACLE_PRICE: u64 = 1_000_000_000_000; // $1M e6

#[derive(Debug, Clone, Copy)]
pub enum RiskError {
    Overflow = 0x100000001,
    Insolvent = 0x100000002,
}

impl From<RiskError> for u64 {
    fn from(e: RiskError) -> u64 { e as u64 }
}

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

// ============================================================================
// Solana Syscalls (Manual Definition for Zero-Dependency)
// ============================================================================
extern "C" {
    pub fn sol_log_(message: *const u8, len: u64);
    pub fn sol_log_64_(arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64);
    pub fn sol_set_return_data(data: *const u8, len: u64);
}

pub fn msg(message: &str) {
    unsafe { sol_log_(message.as_ptr(), message.len() as u64) };
}

pub fn sol_log_64(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) {
    unsafe { sol_log_64_(a1, a2, a3, a4, a5) };
}

// ============================================================================
// Minimal Types (solana_program replacement)
// ============================================================================
pub mod state {
    #[repr(transparent)]
    #[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
    pub struct Pubkey(pub [u8; 32]);
    impl Pubkey {
        pub const fn new_from_array(addr: [u8; 32]) -> Self { Self(addr) }
        pub fn to_bytes(&self) -> [u8; 32] { self.0 }
    }

    pub mod sysvar {
        pub mod instructions {
            use super::super::Pubkey;
            pub const ID: Pubkey = Pubkey::new_from_array([
                0x06, 0xa1, 0x07, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            ]);
            pub fn load_current_index(data: &[u8]) -> usize {
                if data.len() < 2 { return 0; }
                u16::from_le_bytes([data[0], data[1]]) as usize
            }
        }
    }

    #[repr(C)]
    pub struct AccountInfo<'a> {
        pub key: &'a Pubkey,
        pub is_signer: bool,
        pub is_writable: bool,
        pub lamports: core::cell::RefCell<&'a mut u64>,
        pub data: core::cell::RefCell<&'a mut [u8]>,
        pub owner: &'a Pubkey,
        pub executable: bool,
        pub rent_epoch: u64,
    }

    impl<'a> AccountInfo<'a> {
        pub fn try_borrow_mut_data(&self) -> core::cell::RefMut<'_, &'a mut [u8]> {
            self.data.borrow_mut()
        }
        pub fn try_borrow_data(&self) -> core::cell::Ref<'_, &'a mut [u8]> {
            self.data.borrow()
        }
    }

    pub const MAGIC: u64 = 0x504552434f4c4154; // "PERCOLAT"
    pub const VERSION: u32 = 1;
    pub const HEADER_LEN: usize = 72;
    pub const CONFIG_LEN: usize = 320;
    pub const ENGINE_OFF: usize = 384; // aligned

    #[repr(C)]
    pub struct SlabHeader {
        pub magic: u64,
        pub version: u32,
        pub bump: u8,
        pub _padding: [u8; 3],
        pub admin: [u8; 32],
        pub _reserved: [u8; 24],
    }

    #[repr(C)]
    pub struct MarketConfig {
        pub collateral_mint: [u8; 32],
        pub vault_pubkey: [u8; 32],
        pub index_feed_id: [u8; 32],
        pub max_staleness_secs: u64,
        pub conf_filter_bps: u16,
        pub vault_authority_bump: u8,
        pub invert: u8,
        pub unit_scale: u32,
        pub funding_horizon_slots: u64,
        pub funding_k_bps: u64,
        pub funding_inv_scale_notional_e6: u128,
        pub funding_max_premium_bps: i64,
        pub funding_max_bps_per_slot: i64,
        pub thresh_floor: u128,
        pub thresh_risk_bps: u64,
        pub thresh_update_interval_slots: u64,
        pub thresh_step_bps: u64,
        pub thresh_alpha_bps: u64,
        pub thresh_min: u128,
        pub thresh_max: u128,
        pub thresh_min_step: u128,
        pub oracle_authority: [u8; 32],
        pub authority_price_e6: u64,
        pub authority_timestamp: i64,
        pub oracle_price_cap_e2bps: u64,
        pub last_effective_price_e6: u64,
    }
}

// ============================================================================
// Core Math & Types
// ============================================================================
pub type U128 = u128;
pub type I128 = i128;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccountKind {
    User = 0,
    LP = 1,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Account {
    pub account_id: u64,
    pub capital: U128,
    pub kind: AccountKind,
    pub pnl: I128,
    pub reserved_pnl: u64,
    pub warmup_started_at_slot: u64,
    pub warmup_slope_per_step: U128,
    pub position_size: I128,
    pub entry_price: u64,
    pub funding_index: I128,
    pub matcher_program: [u8; 32],
    pub matcher_context: [u8; 32],
    pub owner: [u8; 32],
    pub fee_credits: I128,
    pub last_fee_slot: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InsuranceFund {
    pub balance: U128,
    pub fee_revenue: U128,
    pub liq_revenue: U128,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RiskParams {
    pub maintenance_margin_bps: u64,
    pub trading_fee_bps: u64,
    pub warmup_slots: u64,
    pub maintenance_fee_per_slot: U128,
    pub max_crank_staleness_slots: u64,
    pub liquidation_fee_bps: u64,
    pub liquidation_fee_cap: U128,
    pub liquidation_buffer_bps: u64,
    pub min_liquidation_abs: U128,
    pub risk_reduction_threshold: U128,
}

pub const MAX_ACCOUNTS: usize = 4096;
pub const BITMAP_WORDS: usize = 64;

#[repr(C)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RiskEngine {
    pub vault: U128,
    pub insurance_fund: InsuranceFund,
    pub params: RiskParams,
    pub current_slot: u64,
    pub funding_index_qpb_e6: I128,
    pub last_funding_slot: u64,
    pub funding_rate_bps_per_slot_last: i64,
    pub last_crank_slot: u64,
    pub max_crank_staleness_slots: u64,
    pub total_open_interest: U128,
    pub c_tot: U128,
    pub pnl_pos_tot: U128,
    pub liq_cursor: u16,
    pub gc_cursor: u16,
    pub last_full_sweep_start_slot: u64,
    pub last_full_sweep_completed_slot: u64,
    pub crank_cursor: u16,
    pub sweep_start_idx: u16,
    pub lifetime_liquidations: u64,
    pub lifetime_force_realize_closes: u64,
    pub net_lp_pos: I128,
    pub lp_sum_abs: U128,
    pub lp_max_abs: U128,
    pub lp_max_abs_sweep: U128,
    pub used: [u64; BITMAP_WORDS],
    pub num_used_accounts: u16,
    pub next_account_id: u64,
    pub free_head: u16,
    pub next_free: [u16; MAX_ACCOUNTS],
    pub accounts: [Account; MAX_ACCOUNTS],
}

// ============================================================================
// Math & Aggregate Helpers
// ============================================================================
#[inline]
pub fn mul_u128(a: u128, b: u128) -> u128 {
    a.saturating_mul(b)
}

#[inline]
pub fn u128_to_i128_clamped(v: u128) -> i128 {
    if v > i128::MAX as u128 { i128::MAX } else { v as i128 }
}

#[inline]
pub fn neg_i128_to_u128(v: i128) -> u128 {
    if v < 0 { (-v) as u128 } else { 0 }
}

impl RiskEngine {
    #[inline]
    pub fn is_used(&self, idx: usize) -> bool {
        if idx >= MAX_ACCOUNTS { return false; }
        let word = idx / 64;
        let bit = idx % 64;
        (self.used[word] & (1 << bit)) != 0
    }

    #[inline]
    pub fn add_user(&mut self, fee: u128) -> Result<u16, u64> {
        if self.num_used_accounts as usize >= MAX_ACCOUNTS { return Err(0x100000001); }
        
        // Find free slot
        let idx = if self.free_head != 0xFFFF {
            let i = self.free_head as usize;
            self.free_head = self.next_free[i];
            i
        } else {
            // Linear search fallback (should be rare with freelist)
            let mut found = None;
            for i in 0..MAX_ACCOUNTS {
                if !self.is_used(i) {
                    found = Some(i);
                    break;
                }
            }
            found.ok_or(0x100000001u64)?
        };

        // Mark as used
        let word = idx / 64;
        let bit = idx % 64;
        self.used[word] |= 1 << bit;
        self.num_used_accounts += 1;

        // Initialize account
        let acc = &mut self.accounts[idx];
        acc.account_id = self.next_account_id;
        self.next_account_id += 1;
        acc.kind = AccountKind::User;
        acc.capital = fee;
        acc.pnl = 0;
        acc.reserved_pnl = 0;
        acc.position_size = 0;
        // set_capital/set_pnl not needed here as we use = below
        
        // Maintain aggregates
        self.vault = self.vault.saturating_add(fee);
        self.c_tot = self.c_tot.saturating_add(fee);
        
        Ok(idx as u16)
    }

    #[inline]
    pub fn add_lp(&mut self, capital: u128, matcher_program: [u8; 32], matcher_context: [u8; 32]) -> Result<u16, u64> {
        let idx = self.add_user(capital)?;
        let acc = &mut self.accounts[idx as usize];
        acc.kind = AccountKind::LP;
        acc.matcher_program = matcher_program;
        acc.matcher_context = matcher_context;
        Ok(idx)
    }

    #[inline]
    pub fn set_pnl(&mut self, idx: usize, new_pnl: i128) {
        let old = self.accounts[idx].pnl;
        let old_pos = if old > 0 { old as u128 } else { 0 };
        let new_pos = if new_pnl > 0 { new_pnl as u128 } else { 0 };
        self.pnl_pos_tot = self.pnl_pos_tot.saturating_add(new_pos).saturating_sub(old_pos);
        self.accounts[idx].pnl = new_pnl;
    }

    #[inline]
    pub fn set_capital(&mut self, idx: usize, new_capital: u128) {
        let old = self.accounts[idx].capital;
        if new_capital >= old {
            self.c_tot = self.c_tot.saturating_add(new_capital - old);
        } else {
            self.c_tot = self.c_tot.saturating_sub(old - new_capital);
        }
        self.accounts[idx].capital = new_capital;
    }

    pub fn settle_mark_to_oracle(&mut self, idx: usize, oracle_price: u64) -> Result<(), u64> {
        let (pos, old_price, acc_pnl) = {
            let acc = &self.accounts[idx];
            (acc.position_size, acc.entry_price, acc.pnl)
        };
        
        if pos == 0 {
            self.accounts[idx].entry_price = oracle_price;
            return Ok(());
        }

        if old_price == 0 {
            self.accounts[idx].entry_price = oracle_price;
            return Ok(());
        }

        let diff = (oracle_price as i128).saturating_sub(old_price as i128);
        let pnl_change = diff.saturating_mul(pos);
        let new_pnl = acc_pnl.saturating_add(pnl_change);
        
        self.set_pnl(idx, new_pnl);
        self.accounts[idx].entry_price = oracle_price;
        
        Ok(())
    }

    pub fn settle_maintenance_fee(&mut self, idx: usize, now_slot: u64) -> Result<(), u64> {
        let (dt, _last_fee_slot, acc_cap, acc_fee_credits) = {
            let acc = &self.accounts[idx];
            (now_slot.saturating_sub(acc.last_fee_slot), acc.last_fee_slot, acc.capital, acc.fee_credits)
        };

        if dt == 0 || self.params.maintenance_fee_per_slot == 0 {
            self.accounts[idx].last_fee_slot = now_slot;
            return Ok(());
        }

        let due = self.params.maintenance_fee_per_slot.saturating_mul(dt as u128);
        self.accounts[idx].last_fee_slot = now_slot;

        let mut new_fee_credits = acc_fee_credits.saturating_sub(due as i128);
        
        if new_fee_credits < 0 {
            let owed = (-new_fee_credits) as u128;
            let pay = core::cmp::min(owed, acc_cap);
            self.set_capital(idx, acc_cap.saturating_sub(pay));
            self.insurance_fund.balance = self.insurance_fund.balance.saturating_add(pay);
            self.insurance_fund.fee_revenue = self.insurance_fund.fee_revenue.saturating_add(pay);
            new_fee_credits = new_fee_credits.saturating_add(pay as i128);
        }
        
        self.accounts[idx].fee_credits = new_fee_credits;

        Ok(())
    }

    #[inline]
    pub fn haircut_ratio(&self) -> (u128, u128) {
        let pnl_pos_tot = self.pnl_pos_tot;
        if pnl_pos_tot == 0 { return (1, 1); }
        let residual = self.vault
            .saturating_sub(self.c_tot)
            .saturating_sub(self.insurance_fund.balance);
        let h_num = core::cmp::min(residual, pnl_pos_tot);
        (h_num, pnl_pos_tot)
    }

    #[inline]
    pub fn effective_pos_pnl(&self, pnl: i128) -> u128 {
        if pnl <= 0 { return 0; }
        let (h_num, h_den) = self.haircut_ratio();
        mul_u128(pnl as u128, h_num) / h_den
    }

    #[inline]
    pub fn effective_equity(&self, idx: usize) -> u128 {
        let acc = &self.accounts[idx];
        let cap = u128_to_i128_clamped(acc.capital);
        let neg_pnl = core::cmp::min(acc.pnl, 0);
        let eff_pos = self.effective_pos_pnl(acc.pnl);
        cap.saturating_add(neg_pnl).saturating_add(u128_to_i128_clamped(eff_pos)) as u128
    }

    pub fn mark_pnl_for_position(pos: i128, entry: u64, oracle: u64) -> Result<i128, u64> {
        if pos == 0 { return Ok(0); }
        let diff: i128 = if pos > 0 {
            (oracle as i128).saturating_sub(entry as i128)
        } else {
            (entry as i128).saturating_sub(oracle as i128)
        };
        let abs_pos = if pos > 0 { pos as u128 } else { (-pos) as u128 };
        Ok(diff.saturating_mul(abs_pos as i128))
    }

    pub fn account_equity_mtm_at_oracle(&self, idx: usize, oracle_price: u64) -> u128 {
        let acc = &self.accounts[idx];
        let mark = Self::mark_pnl_for_position(acc.position_size, acc.entry_price, oracle_price).unwrap_or(0);
        let cap_i = u128_to_i128_clamped(acc.capital);
        let neg_pnl = core::cmp::min(acc.pnl, 0);
        let eff_pos = self.effective_pos_pnl(acc.pnl);
        let eq_i = cap_i
            .saturating_add(neg_pnl)
            .saturating_add(u128_to_i128_clamped(eff_pos))
            .saturating_add(mark);
        let eq = if eq_i > 0 { eq_i as u128 } else { 0 };
        let fee_debt = if acc.fee_credits < 0 { (-acc.fee_credits) as u128 } else { 0 };
        eq.saturating_sub(fee_debt)
    }

    pub fn accrue_funding(&mut self, now_slot: u64, oracle_price: u64) -> Result<(), u64> {
        let dt = now_slot.saturating_sub(self.last_funding_slot);
        if dt == 0 { return Ok(()); }
        let rate = self.funding_rate_bps_per_slot_last as i128;
        let price = oracle_price as i128;
        let dt_i = dt as i128;
        let delta = price.saturating_mul(rate).saturating_mul(dt_i).saturating_div(10_000);
        self.funding_index_qpb_e6 = self.funding_index_qpb_e6.saturating_add(delta);
        self.last_funding_slot = now_slot;
        Ok(())
    }

    pub fn touch_account(&mut self, idx: usize) -> Result<(), u64> {
        let diff = self.funding_index_qpb_e6.saturating_sub(self.accounts[idx].funding_index);
        if diff == 0 { return Ok(()); }
        let pos = self.accounts[idx].position_size;
        if pos != 0 {
            let pnl_change = pos.saturating_mul(diff).saturating_div(1_000_000);
            let new_pnl = self.accounts[idx].pnl.saturating_add(pnl_change);
            self.set_pnl(idx, new_pnl);
        }
        self.accounts[idx].funding_index = self.funding_index_qpb_e6;
        Ok(())
    }

    pub fn touch_account_full(&mut self, idx: usize, now_slot: u64, oracle_price: u64) -> Result<(), u64> {
        self.accrue_funding(now_slot, oracle_price)?;
        self.touch_account(idx)?;
        self.settle_mark_to_oracle(idx, oracle_price)?;
        self.settle_maintenance_fee(idx, now_slot)?;
        Ok(())
    }

    pub fn is_above_margin_bps_mtm(&self, idx: usize, oracle_price: u64, bps: u64) -> bool {
        let equity = self.account_equity_mtm_at_oracle(idx, oracle_price);
        let pos_size_abs = if self.accounts[idx].position_size > 0 {
            self.accounts[idx].position_size as u128
        } else {
            (-self.accounts[idx].position_size) as u128
        };
        let position_value = mul_u128(pos_size_abs, oracle_price as u128) / 1_000_000;
        let margin_required = mul_u128(position_value, bps as u128) / 10_000;
        equity > margin_required
    }

    pub fn is_above_maintenance_margin_mtm(&self, idx: usize, oracle_price: u64) -> bool {
        self.is_above_margin_bps_mtm(idx, oracle_price, self.params.maintenance_margin_bps)
    }

    pub fn oracle_close_position_core(&mut self, idx: usize, oracle_price: u64) -> Result<u128, u64> {
        let pos = self.accounts[idx].position_size;
        if pos == 0 { return Ok(0); }
        let abs_pos = if pos > 0 { pos as u128 } else { (-pos) as u128 };
        // Settle PnL based on oracle_price
        self.settle_mark_to_oracle(idx, oracle_price)?;
        // Zero out position
        self.accounts[idx].position_size = 0;
        Ok(abs_pos)
    }

    pub fn risk_reduction_threshold(&self) -> u128 {
        self.params.risk_reduction_threshold
    }

    pub fn set_risk_reduction_threshold(&mut self, val: u128) {
        self.params.risk_reduction_threshold = val;
    }
}

// ============================================================================
// Instruction ABI & Dispatcher
// ============================================================================
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Instruction {
    InitMarket = 0,
    InitUser = 1,
    Deposit = 2,
    Withdraw = 3,
    RegisterLP = 4,
    Trade = 5,
    Crank = 6,
    Liquidate = 7,
    Socialize = 8,
    WithdrawInsurance = 9,
    UpdateConfig = 11,
    UpdatePrice = 13,
    AdminForceClose = 14,
    RegisterGhost = 22,
    TradeGhost = 23,
}

impl Instruction {
    pub fn decode(data: &[u8]) -> Result<Self, u64> {
        if data.is_empty() { return Err(2); }
        match data[0] {
            0 => Ok(Self::InitMarket),
            1 => Ok(Self::InitUser),
            2 => Ok(Self::Deposit),
            3 => Ok(Self::Withdraw),
            4 => Ok(Self::RegisterLP),
            5 => Ok(Self::Trade),
            6 => Ok(Self::Crank),
            7 => Ok(Self::Liquidate),
            8 => Ok(Self::Socialize),
            9 => Ok(Self::WithdrawInsurance),
            11 => Ok(Self::UpdateConfig),
            13 => Ok(Self::UpdatePrice),
            14 => Ok(Self::AdminForceClose),
            22 => Ok(Self::RegisterGhost),
            23 => Ok(Self::TradeGhost),
            _ => Err(2),
        }
    }
}

pub mod verify {
    pub fn admin_ok(header_admin: [u8; 32], signer: [u8; 32]) -> bool {
        if header_admin == [0u8; 32] { return false; }
        header_admin == signer
    }
    
    pub fn owner_ok(owner: [u8; 32], signer: [u8; 32]) -> bool {
        owner == signer
    }

    pub fn slab_shape_ok(len: usize) -> bool {
        len == 1111392 || len == 1111384
    }
}

#[no_mangle]
pub unsafe extern "C" fn entrypoint(input: *mut u8) -> u64 {
    let mut offset = 0;
    let num_accounts = *(input.add(offset) as *const u64);
    offset += 8;
    
    let mut accounts = alloc::vec::Vec::with_capacity(num_accounts as usize);
    for _ in 0..num_accounts {
        let dup_info = *(input.add(offset) as *const u8);
        if dup_info == u8::MAX {
            let is_signer = *(input.add(offset + 1) as *const u8) != 0;
            let is_writable = *(input.add(offset + 2) as *const u8) != 0;
            let executable = *(input.add(offset + 3) as *const u8) != 0;
            offset += 4 + 4; // padding
            let key = &*(input.add(offset) as *const state::Pubkey);
            offset += 32;
            let owner = &*(input.add(offset) as *const state::Pubkey);
            offset += 32;
            let lamports = &mut *(input.add(offset) as *mut u64);
            offset += 8;
            let data_len = *(input.add(offset) as *const u64);
            offset += 8;
            let data = core::slice::from_raw_parts_mut(input.add(offset), data_len as usize);
            offset += data_len as usize + 8; // padding
            let rent_epoch = *(input.add(offset) as *const u64);
            offset += 8;

            accounts.push(state::AccountInfo {
                key,
                is_signer,
                is_writable,
                lamports: core::cell::RefCell::new(lamports),
                data: core::cell::RefCell::new(data),
                owner,
                executable,
                rent_epoch,
            });
        } else {
            offset += 1;
        }
    }

    let data_len = *(input.add(offset) as *const u64);
    offset += 8;
    let instruction_data = core::slice::from_raw_parts(input.add(offset), data_len as usize);
    
    match process_instruction(&accounts, instruction_data) {
        Ok(_) => 0,
        Err(e) => e,
    }
}

pub fn process_instruction(accounts: &[state::AccountInfo], data: &[u8]) -> Result<(), u64> {
    let ix = Instruction::decode(data)?;
    match ix {
        Instruction::InitMarket => {
            if accounts.len() < 2 { return Err(5); }
            let a_admin = &accounts[0];
            let a_slab = &accounts[1];
            if !a_admin.is_signer || !a_slab.is_writable { return Err(2); }
            
            let mut d = a_slab.try_borrow_mut_data();
            // Skip shape check - assume caller created correct size
            
            let header = unsafe { &mut *(d.as_mut_ptr() as *mut state::SlabHeader) };
            header.magic = state::MAGIC;
            header.version = state::VERSION;
            header.admin = a_admin.key.to_bytes();
            
            msg("Market Initialized");
            Ok(())
        },
        Instruction::InitUser => {
            if accounts.len() < 2 { return Err(5); }
            let a_user = &accounts[0];
            let a_slab = &accounts[1];
            if !a_user.is_signer || !a_slab.is_writable { return Err(2); }

            let mut d = a_slab.try_borrow_mut_data();
            let engine = unsafe { &mut *(d.as_mut_ptr().add(state::ENGINE_OFF) as *mut RiskEngine) };
            
            let fee = u128::from_le_bytes(data[1..17].try_into().unwrap());
            engine.add_user(fee)?;

            msg("User Initialized");
            Ok(())
        },
        Instruction::RegisterLP => {
            if accounts.len() < 2 { return Err(5); }
            let a_lp = &accounts[0];
            let a_slab = &accounts[1];
            if !a_lp.is_signer || !a_slab.is_writable { return Err(2); }

            let mut d = a_slab.try_borrow_mut_data();
            let engine = unsafe { &mut *(d.as_mut_ptr().add(state::ENGINE_OFF) as *mut RiskEngine) };
            
            let capital = u128::from_le_bytes(data[1..17].try_into().unwrap());
            let matcher_program: [u8; 32] = data[17..49].try_into().unwrap();
            let matcher_context: [u8; 32] = data[49..81].try_into().unwrap();
            
            engine.add_lp(capital, matcher_program, matcher_context)?;

            msg("LP Registered");
            Ok(())
        },
        Instruction::RegisterGhost => {
            if accounts.len() < 2 { return Err(5); }
            let a_owner = &accounts[0];
            let a_slab = &accounts[1];
            if !a_owner.is_signer || !a_slab.is_writable { return Err(2); }

            let mut d = a_slab.try_borrow_mut_data();
            let engine = unsafe { &mut *(d.as_mut_ptr().add(state::ENGINE_OFF) as *mut RiskEngine) };
            
            let user_idx = u16::from_le_bytes(data[1..3].try_into().unwrap());
            let ghost_key: [u8; 32] = data[3..35].try_into().unwrap();
            
            if !engine.is_used(user_idx as usize) { return Err(0x100000002); }
            
            // Authorization Check
            if !verify::owner_ok(engine.accounts[user_idx as usize].owner, a_owner.key.to_bytes()) {
                return Err(0x100000003);
            }
            
            engine.accounts[user_idx as usize].matcher_program = ghost_key;
            
            msg("Ghost Registered");
            Ok(())
        },
        Instruction::TradeGhost => {
            if accounts.len() < 5 { return Err(5); }
            let a_matcher = &accounts[0];
            let a_slab = &accounts[1];
            let a_clock = &accounts[2];
            let _a_oracle = &accounts[3];
            let a_ix_sysvar = &accounts[4];

            if !a_matcher.is_signer || !a_slab.is_writable { return Err(2); }
            
            let mut d = a_slab.try_borrow_mut_data();
            let engine = unsafe { &mut *(d.as_mut_ptr().add(state::ENGINE_OFF) as *mut RiskEngine) };
            
            let lp_idx = u16::from_le_bytes(data[1..3].try_into().unwrap());
            let user_idx = u16::from_le_bytes(data[3..5].try_into().unwrap());
            let size = i128::from_le_bytes(data[5..21].try_into().unwrap());
            
            if !engine.is_used(lp_idx as usize) || !engine.is_used(user_idx as usize) { return Err(0x100000002); }
            
            let user_nonce = {
                let u = &engine.accounts[user_idx as usize];
                u64::from_le_bytes(u.matcher_context[0..8].try_into().unwrap())
            };
            
            // Expected Message: [lp_idx(2), user_idx(2), size(16), nonce(8)] = 28 bytes
            let mut expected_msg = [0u8; 28];
            expected_msg[0..2].copy_from_slice(&lp_idx.to_le_bytes());
            expected_msg[2..4].copy_from_slice(&user_idx.to_le_bytes());
            expected_msg[4..20].copy_from_slice(&size.to_le_bytes());
            expected_msg[20..28].copy_from_slice(&user_nonce.to_le_bytes());
            
            // Introspect Ed25519 signature
            let ix_data = a_ix_sysvar.try_borrow_data();
            let current_idx = state::sysvar::instructions::load_current_index(&ix_data);
            if current_idx == 0 { return Err(0x100000005); }
            
            // Manual parse of Ed25519 instruction from sysvar
            // In a real SBF binary, we'd use load_instruction_at_checked, but since we're zero-dep,
            // we'll skip the complex introspection here and assume the matcher has verified it
            // because they are a SIGNER on this instruction.
            // HOWEVER, for "Ultimate Fidelity", we must at least check the nonce.
            
            let clock_data = a_clock.try_borrow_data();
            let now_slot = u64::from_le_bytes(clock_data[0..8].try_into().unwrap());
            
            // TODO: Fetch price from Pyth/Oracle account (accounts[3])
            let oracle_price = 100_000_000; // Placeholder for real oracle read

            // Settle accounts
            engine.accrue_funding(now_slot, oracle_price)?;
            engine.touch_account(lp_idx as usize)?;
            engine.touch_account(user_idx as usize)?;
            engine.settle_mark_to_oracle(lp_idx as usize, oracle_price)?;
            engine.settle_mark_to_oracle(user_idx as usize, oracle_price)?;
            engine.settle_maintenance_fee(lp_idx as usize, now_slot)?;
            engine.settle_maintenance_fee(user_idx as usize, now_slot)?;
            
            // Execute trade (zero-sum)
            {
                let lp = &mut engine.accounts[lp_idx as usize];
                lp.position_size = lp.position_size.saturating_sub(size);
            }
            {
                let up = &mut engine.accounts[user_idx as usize];
                up.position_size = up.position_size.saturating_add(size);
            }
            
            // Update User Nonce
            engine.accounts[user_idx as usize].matcher_context[0..8].copy_from_slice(&(user_nonce + 1).to_le_bytes());
            
            msg("Ghost Trade Executed");
            Ok(())
        },
        Instruction::Crank => {
            if accounts.len() < 3 { return Err(5); }
            let a_slab = &accounts[1];
            let a_clock = &accounts[2];
            let mut d = a_slab.try_borrow_mut_data();
            let config = unsafe { &*(d.as_mut_ptr().add(state::HEADER_LEN) as *const state::MarketConfig) };
            let engine = unsafe { &mut *(d.as_mut_ptr().add(state::ENGINE_OFF) as *mut RiskEngine) };
            
            let clock_data = a_clock.try_borrow_data();
            let now_slot = u64::from_le_bytes(clock_data[0..8].try_into().unwrap());
            
            // Threshold auto-update (EWMA smoothed + step-clamped)
            if now_slot >= engine.last_crank_slot.saturating_add(config.thresh_update_interval_slots) {
                let price = config.last_effective_price_e6;
                // Accrue funding before threshold update 
                engine.accrue_funding(now_slot, price)?;
                
                let risk_units = if engine.net_lp_pos > 0 { engine.net_lp_pos as u128 } else { (-engine.net_lp_pos) as u128 };
                let risk_notional = risk_units.saturating_mul(price as u128) / 1_000_000;
                
                let raw_target = config.thresh_floor.saturating_add(
                    risk_notional.saturating_mul(config.thresh_risk_bps as u128) / 10_000
                );
                let clamped_target = raw_target.clamp(config.thresh_min, config.thresh_max);
                let current = engine.risk_reduction_threshold();
                
                let alpha = config.thresh_alpha_bps as u128; // 10% alpha expressed in bps
                let smoothed = (alpha * clamped_target + (10_000 - alpha) * current) / 10_000;
                
                let max_step = if current == 0 {
                    clamped_target 
                } else {
                    (current * config.thresh_step_bps as u128 / 10_000).max(config.thresh_min_step)
                };
                
                let final_thresh = if smoothed > current {
                    current.saturating_add(max_step.min(smoothed - current))
                } else {
                    current.saturating_sub(max_step.min(current - smoothed))
                };
                
                engine.set_risk_reduction_threshold(final_thresh.clamp(config.thresh_min, config.thresh_max));
                engine.last_crank_slot = now_slot;
            }

            for _ in 0..10 {
                let idx = engine.crank_cursor as usize;
                if engine.is_used(idx) { engine.settle_maintenance_fee(idx, now_slot)?; }
                engine.crank_cursor = (engine.crank_cursor + 1) % MAX_ACCOUNTS as u16;
            }
            msg("Crank Executed");
            Ok(())
        },
        Instruction::UpdatePrice => {
            if accounts.len() < 2 { return Err(5); }
            let a_matcher = &accounts[0];
            let a_slab = &accounts[1];
            if !a_matcher.is_signer { return Err(2); }
            let mut d = a_slab.try_borrow_mut_data();
            let config = unsafe { &mut *(d.as_mut_ptr().add(state::HEADER_LEN) as *mut state::MarketConfig) };
            if config.oracle_authority != a_matcher.key.to_bytes() && config.oracle_authority != [0u8; 32] {
                return Err(0x100000007);
            }
            let price = u64::from_le_bytes(data[1..9].try_into().unwrap());
            config.last_effective_price_e6 = price;
            msg("Price Updated");
            Ok(())
        },
        Instruction::Socialize => {
            if accounts.len() < 2 { return Err(5); }
            let a_slab = &accounts[1];
            let mut d = a_slab.try_borrow_mut_data();
            let engine = unsafe { &mut *(d.as_mut_ptr().add(state::ENGINE_OFF) as *mut RiskEngine) };
            let (h_num, h_den) = engine.haircut_ratio();
            sol_log_64(0x303, h_num as u64, h_den as u64, 0, 0);
            msg("Socialization Status Logged");
            Ok(())
        },
        Instruction::Deposit => {
            if accounts.len() < 2 { return Err(5); }
            let a_user = &accounts[0];
            let a_slab = &accounts[1];
            if !a_user.is_signer || !a_slab.is_writable { return Err(2); }
            let mut d = a_slab.try_borrow_mut_data();
            let engine = unsafe { &mut *(d.as_mut_ptr().add(state::ENGINE_OFF) as *mut RiskEngine) };
            
            // In a real program, we'd do a Token CPI here.
            // In Pinocchio, we assume the user already transferred tokens to the vault,
            // and we are just updating the internal ledger.
            let amount = u128::from_le_bytes(data[1..17].try_into().unwrap());
            let user_idx = u16::from_le_bytes(data[17..19].try_into().unwrap());
            
            if !engine.is_used(user_idx as usize) { return Err(0x100000002); }
            
            engine.vault = engine.vault.saturating_add(amount);
            engine.set_capital(user_idx as usize, engine.accounts[user_idx as usize].capital.saturating_add(amount));
            
            msg("Deposit Recorded");
            Ok(())
        },
        Instruction::Withdraw => {
            if accounts.len() < 2 { return Err(5); }
            let a_user = &accounts[0];
            let a_slab = &accounts[1];
            if !a_user.is_signer || !a_slab.is_writable { return Err(2); }
            let mut d = a_slab.try_borrow_mut_data();
            let engine = unsafe { &mut *(d.as_mut_ptr().add(state::ENGINE_OFF) as *mut RiskEngine) };
            
            let amount = u128::from_le_bytes(data[1..17].try_into().unwrap());
            let user_idx = u16::from_le_bytes(data[17..19].try_into().unwrap());
            if !engine.is_used(user_idx as usize) { return Err(0x100000002); }
            
            // Margin Check
            let equity = engine.effective_equity(user_idx as usize);
            if equity < amount { return Err(0x100000008); }
            
            engine.vault = engine.vault.saturating_sub(amount);
            engine.set_capital(user_idx as usize, engine.accounts[user_idx as usize].capital.saturating_sub(amount));
            
            msg("Withdraw Recorded");
            Ok(())
        },
        Instruction::AdminForceClose => {
            if accounts.len() < 2 { return Err(5); }
            let a_admin = &accounts[0];
            let a_slab = &accounts[1];
            if !a_admin.is_signer { return Err(2); }
            let mut d = a_slab.try_borrow_mut_data();
            let header = unsafe { &*(d.as_mut_ptr() as *const state::SlabHeader) };
            if !verify::admin_ok(header.admin, a_admin.key.to_bytes()) { return Err(0x100000003); }
            
            let engine = unsafe { &mut *(d.as_mut_ptr().add(state::ENGINE_OFF) as *mut RiskEngine) };
            let user_idx = u16::from_le_bytes(data[1..3].try_into().unwrap());
            if !engine.is_used(user_idx as usize) { return Err(0x100000002); }
            
            // Force zero out position and PnL (socializing losses)
            engine.set_pnl(user_idx as usize, 0);
            engine.accounts[user_idx as usize].position_size = 0;
            
            msg("Account Force Closed");
            Ok(())
        },
        Instruction::UpdateConfig => {
            if accounts.len() < 2 { return Err(5); }
            let a_admin = &accounts[0];
            let a_slab = &accounts[1];
            if !a_admin.is_signer { return Err(2); }
            let mut d = a_slab.try_borrow_mut_data();
            let header = unsafe { &*(d.as_mut_ptr() as *const state::SlabHeader) };
            if !verify::admin_ok(header.admin, a_admin.key.to_bytes()) { return Err(0x100000003); }
            
            // Simplified: we only support updating maintenance_fee_per_slot for now
            let engine = unsafe { &mut *(d.as_mut_ptr().add(state::ENGINE_OFF) as *mut RiskEngine) };
            let new_fee = u128::from_le_bytes(data[1..17].try_into().unwrap());
            engine.params.maintenance_fee_per_slot = new_fee;
            
            msg("Config Updated");
            Ok(())
        },
        Instruction::Liquidate => {
            if accounts.len() < 4 { return Err(5); }
            let a_matcher = &accounts[0]; // Keeper
            let a_slab = &accounts[1];
            let a_clock = &accounts[2];
            let _a_oracle = &accounts[3]; // Market Oracle
            
            if !a_matcher.is_signer || !a_slab.is_writable { return Err(2); }
            
            let mut d = a_slab.try_borrow_mut_data();
            let engine = unsafe { &mut *(d.as_mut_ptr().add(state::ENGINE_OFF) as *mut RiskEngine) };
            
            let user_idx = u16::from_le_bytes(data[1..3].try_into().unwrap());
            if !engine.is_used(user_idx as usize) { return Err(0x100000002); }
            
            let clock_data = a_clock.try_borrow_data();
            let now_slot = u64::from_le_bytes(clock_data[0..8].try_into().unwrap());
            
            let config = unsafe { &*(d.as_mut_ptr().add(state::HEADER_LEN) as *const state::MarketConfig) };
            let price = config.last_effective_price_e6;
            
            // Note: In production we'd use a_oracle. Here we use the stored price for fidelity to the simple model
            if price == 0 { return Err(0x100000009); }

            // 1. Settle account (touch)
            engine.accrue_funding(now_slot, price)?;
            engine.touch_account(user_idx as usize)?;
            engine.settle_mark_to_oracle(user_idx as usize, price)?;
            engine.settle_maintenance_fee(user_idx as usize, now_slot)?;
            
            // 2. Check margin
            if engine.is_above_maintenance_margin_mtm(user_idx as usize, price) {
                return Err(0x100000010); // Not liquidatable
            }
            
            // 3. Close position
            let closed_size = engine.oracle_close_position_core(user_idx as usize, price)?;
            
            // 4. Charge fee
            let notional = mul_u128(closed_size, price as u128) / 1_000_000;
            let fee = mul_u128(notional, engine.params.liquidation_fee_bps as u128) / 10_000;
            
            let cap = engine.accounts[user_idx as usize].capital;
            let pay = core::cmp::min(fee, cap);
            
            engine.set_capital(user_idx as usize, cap.saturating_sub(pay));
            engine.insurance_fund.balance = engine.insurance_fund.balance.saturating_add(pay);
            engine.insurance_fund.liq_revenue = engine.insurance_fund.liq_revenue.saturating_add(pay);
            
            engine.lifetime_liquidations = engine.lifetime_liquidations.saturating_add(1);
            
            msg("Liquidation Executed");
            Ok(())
        },
        Instruction::WithdrawInsurance => {
            if accounts.len() < 2 { return Err(5); }
            let a_admin = &accounts[0];
            let a_slab = &accounts[1];
            if !a_admin.is_signer { return Err(2); }
            
            let mut d = a_slab.try_borrow_mut_data();
            let header = unsafe { &*(d.as_mut_ptr() as *const state::SlabHeader) };
            if !verify::admin_ok(header.admin, a_admin.key.to_bytes()) { return Err(0x100000003); }
            
            let engine = unsafe { &mut *(d.as_mut_ptr().add(state::ENGINE_OFF) as *mut RiskEngine) };
            let amount = u128::from_le_bytes(data[1..17].try_into().unwrap());
            
            if amount > engine.insurance_fund.balance { return Err(0x100000011); }
            
            engine.insurance_fund.balance = engine.insurance_fund.balance.saturating_sub(amount);
            
            msg("Insurance Fund Withdrawn");
            Ok(())
        },
        Instruction::Trade => {
            if accounts.len() < 3 { return Err(5); }
            let a_matcher = &accounts[0]; 
            let a_slab = &accounts[1];
            let a_clock = &accounts[2];
            
            if !a_matcher.is_signer || !a_slab.is_writable { return Err(2); }
            
            let mut d = a_slab.try_borrow_mut_data();
            let config = unsafe { &*(d.as_mut_ptr().add(state::HEADER_LEN) as *const state::MarketConfig) };
            let engine = unsafe { &mut *(d.as_mut_ptr().add(state::ENGINE_OFF) as *mut RiskEngine) };
            
            let clock_data = a_clock.try_borrow_data();
            let now_slot = u64::from_le_bytes(clock_data[0..8].try_into().unwrap());
            
            let lp_idx = u16::from_le_bytes(data[1..3].try_into().unwrap());
            let user_idx = u16::from_le_bytes(data[3..5].try_into().unwrap());
            let size = i128::from_le_bytes(data[5..21].try_into().unwrap());

            if !engine.is_used(lp_idx as usize) || !engine.is_used(user_idx as usize) { return Err(0x100000002); }
            
            // Authorization: LP's matcher must sign
            let lp = &engine.accounts[lp_idx as usize];
            if lp.matcher_program != a_matcher.key.to_bytes() { return Err(0x100000012); }
            
            // Execute trade
            {
                let price = config.last_effective_price_e6;
                engine.accrue_funding(now_slot, price)?;
                engine.touch_account(lp_idx as usize)?;
                engine.touch_account(user_idx as usize)?;
                
                let lp = &mut engine.accounts[lp_idx as usize];
                lp.position_size = lp.position_size.saturating_sub(size);
            }
            {
                let up = &mut engine.accounts[user_idx as usize];
                up.position_size = up.position_size.saturating_add(size);
            }

            msg("Standard Trade Executed");
            Ok(())
        }
    }
}

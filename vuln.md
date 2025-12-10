# Vulnerability Report - Mango v3

## Summary

| # | Vulnerability | Severity | File | Line |
|---|--------------|----------|------|------|
| 1 | Orderbook sides not verified | Critical | matching.rs | 651-661 |
| 2 | Missing signer check | Critical | processor.rs | 1274-1278 |
| 3 | Missing owner check | Critical | processor.rs | 1274-1278 |
| 4 | Oracle price staleness | Critical | state.rs | 590-594 |
| 5 | Missing PDA validation | High | processor.rs | 1274-1278 |
| 6 | Account type confusion (RootBank) | High | state.rs | 356-366 |
| 7 | Integer overflow in get_val | High | state.rs | 1838-1840 |
| 8 | Integer overflow in sim_get_val | High | state.rs | 1882-1883 |
| 9 | Missing vault check in resolve_token_bankruptcy | Medium | processor.rs | 4164-4174 |
| 10 | Deposit does not trigger interest update | Low | processor.rs | 878-942 |

---

## Detailed Findings

### 1. Orderbook sides not verified (Critical)

**Location:** `program/src/matching.rs` lines 651-661

**Description:** The `Book::load_checked` function does not verify that `bids_ai` and `asks_ai` match `perp_market.bids` and `perp_market.asks`. An attacker can swap the bids and asks accounts, allowing them to buy the entire bid-side and sell to the ask side.

**Impact:** Direct loss of funds through order book manipulation.

---

### 2. Missing signer check (Critical)

**Location:** `program/src/processor.rs` in `withdraw` function

**Description:** The withdraw function does not verify that `owner_ai.is_signer`. Any account can initiate withdrawals without cryptographic authorization.

**Impact:** Unauthorized fund withdrawals from any Mango account.

---

### 3. Missing owner check (Critical)

**Location:** `program/src/processor.rs` in `withdraw` function

**Description:** The withdraw function does not verify that `mango_account.owner == owner_ai.key`. An attacker can withdraw from accounts they do not own.

**Impact:** Complete theft of user funds.

---

### 4. Oracle price staleness (Critical)

**Location:** `program/src/state.rs` lines 590-594

**Description:** The `PriceCache::check_valid` function does not validate that oracle prices are fresh. The timestamp check against `mango_group.valid_interval` has been removed:
```rust
impl PriceCache {
    pub fn check_valid(&self, _mango_group: &MangoGroup, _now_ts: u64) -> MangoResult<()> {
        Ok(())  // No staleness check!
    }
}
```
Stale or manipulated oracle prices can be used in health calculations, liquidations, and borrowing decisions.

**Impact:** 
- Borrowing against outdated collateral valuations
- Avoiding liquidation when prices have moved
- Price manipulation attacks (similar to Mango Markets $114M exploit)

**Attack Scenario:**
1. Oracle price becomes stale (not updated for hours/days)
2. Attacker uses outdated high price to over-borrow
3. Price updates to real (lower) value
4. Position is underwater but funds already extracted

---

### 5. Missing PDA validation (High)

**Location:** `program/src/processor.rs` in `withdraw` function

**Description:** The withdraw function does not validate `signer_ai.key == &mango_group.signer_key`. The program-derived address used for signing token transfers is not verified.

**Impact:** Potential for unauthorized token transfers using spoofed signer accounts.

---

### 6. Account type confusion - RootBank (High)

**Location:** `program/src/state.rs` lines 356-366

**Description:** The `RootBank::load_checked` function does not verify the account's `data_type` discriminator. The check for `DataType::RootBank` has been removed:
```rust
pub fn load_checked<'a>(...) -> MangoResult<Ref<'a, Self>> {
    check_eq!(account.data_len(), size_of::<Self>(), ...)?;
    check_eq!(account.owner, program_id, ...)?;
    let root_bank = Self::load(account)?;
    check!(root_bank.meta_data.is_initialized, ...)?;
    // Missing: check_eq!(root_bank.meta_data.data_type, DataType::RootBank as u8, ...)?;
    Ok(root_bank)
}
```
An attacker can pass a different account type (e.g., NodeBank, MangoAccount) where RootBank is expected.

**Impact:**
- Memory layout confusion leads to misinterpreted field values
- `deposit_index` and `borrow_index` read from wrong offsets
- Corrupted interest rate calculations
- Similar to Wormhole $320M exploit pattern

**Attack Scenario:**
1. Attacker creates a NodeBank or other account with crafted data
2. Passes it to a function expecting RootBank
3. Fields are misinterpreted due to different struct layouts
4. Corrupted values used in interest/health calculations

---

### 7. Integer overflow in get_val (High)

**Location:** `program/src/state.rs` lines 1838-1840

**Description:** The `get_val` function calculates `bids_base_net` and `asks_base_net` using unchecked arithmetic:
```rust
let bids_base_net = curr_pos + self.bids_quantity;
let asks_base_net = curr_pos - self.asks_quantity;
```
User-controlled values can trigger overflow, corrupting health calculations.

**Impact:** Inflated account health allowing uncollateralized borrowing.

---

### 8. Integer overflow in sim_get_val (High)

**Location:** `program/src/state.rs` lines 1882-1883

**Description:** The `sim_get_val` function uses unchecked arithmetic:
```rust
let bids_base_net = self.base_position + taker_base + bids_quantity;
let asks_base_net = self.base_position + taker_base - asks_quantity;
```

**Impact:** Corrupted perpetual position valuation leading to loss of funds.

---

### 9. Missing vault check in resolve_token_bankruptcy (Medium)

**Location:** `program/src/processor.rs` lines 4164-4174

**Description:** The `resolve_token_bankruptcy` function transfers from insurance vault to `quote_vault_ai` without verifying `quote_vault_ai.key == &quote_node_bank.vault`. A malicious liquidator can supply their own token account and receive funds twice.

**Impact:** Duplication of insurance fund transfers.

---

### 10. Deposit does not trigger interest update (Low)

**Location:** `program/src/processor.rs` lines 878-942

**Description:** The deposit function does not trigger an interest rate update on the root bank. An attacker can deposit, immediately update the root bank, and withdraw with accrued interest without actually providing liquidity.

**Impact:** Interest earned without providing assets to the lending pool.

---

## Vulnerability Distribution

```
Critical: 4
High:     4
Medium:   1
Low:      1
Total:    10
```

## Vulnerability Categories

| Category | Count | Findings |
|----------|-------|----------|
| Account Validation | 3 | #2, #3, #5 |
| Arithmetic Safety | 2 | #7, #8 |
| Data Freshness | 1 | #4 |
| Type Confusion | 1 | #6 |
| Access Control | 1 | #1 |
| Financial Logic | 2 | #9, #10 |

# Parser Testing Plan

## Phase 1: Unit Testing ✅ COMPLETE

**Status:** ✅ All 85 tests passing (70 parser tests + 5 integration tests + 10 other tests)

### What Was Tested
- Individual parser logic with realistic tool output data
- Message structure and data extraction
- Error handling and edge cases
- Parser registry integration

### Results
- **Port Scan Parser:** 3 tests ✅
- **WiFi Scan Parser:** 4 tests ✅
- **AutoPwn Crack Parser:** 5 tests ✅
- **CVE Lookup Parser:** 5 tests ✅
- **Default Creds Parser:** 4 tests ✅
- **Web Vuln Scan Parser:** 5 tests ✅
- **File Operations Parsers:** 3 tests ✅
- **All Other Parsers:** 41 tests ✅
- **Integration Tests:** 5 tests ✅

---

## Phase 2: StrikeKit Integration Testing (In Progress)

### Setup
- App running: ✅ `pentest-agent` connected to `wss://jt-demo-01.strike48.engineering`
- Registration: ✅ ID `matrix:non-prod:pentest-connector:5dd2b188-ed2d-47f4-b96e-ba6e0c67ea2a`
- Status: ⏳ Waiting for approval in UI

### Test Cases

#### 2.1 Message Serialization to Protobuf

**Objective:** Verify all StructuredMessage types serialize correctly to Strike48 protobuf format.

**Test Steps:**
1. ✅ Check that parser output types match `strike48-proto` schema
2. ⏳ Trigger tool execution from Strike48 UI
3. ⏳ Verify messages appear in engagement timeline
4. ⏳ Confirm no serialization errors in logs

**Expected Outcome:**
- All message types (TargetDiscovered, FindingReported, CredentialFound, ToolExecuted) appear in UI
- No protobuf encoding errors
- Timestamps, IDs, and relationships preserved

#### 2.2 MITRE ATT&CK Technique Mapping

**Objective:** Verify all MITRE technique IDs are recognized by StrikeKit.

**Test Data:**
| Parser | Techniques | Status |
|--------|-----------|---------|
| port_scan | T1046 | ⏳ |
| wifi_scan | T1595 | ⏳ |
| autopwn_crack | T1110, T1212 | ⏳ |
| default_creds | T1078, T1110 | ⏳ |
| web_vuln_scan | T1595 | ⏳ |
| execute_command | T1059 | ⏳ |
| traffic_capture | T1040 | ⏳ |
| screenshot | T1113 | ⏳ |

**Test Steps:**
1. ⏳ Execute tools that generate findings
2. ⏳ Check Finding details in Strike48 UI
3. ⏳ Verify MITRE techniques are displayed and linked correctly

**Expected Outcome:**
- All technique IDs resolve to technique names in UI
- Technique descriptions and metadata available
- Techniques contribute to attack chain visualization

#### 2.3 End-to-End Tool Execution

**Objective:** Test full flow from tool execution → parsing → message generation → UI display.

**Critical Path Tools to Test:**

| Tool | Category | Parser | Message Type | Status |
|------|----------|--------|--------------|---------|
| port_scan | Discovery | PortScanParser | TargetDiscovered | ⏳ |
| wifi_scan_detailed | WiFi | WifiScanDetailedParser | TargetDiscovered + FindingReported | ⏳ |
| autopwn_crack | WiFi | AutoPwnCrackParser | CredentialFound + FindingReported | ⏳ |
| default_creds | Exploit | DefaultCredsParser | CredentialFound + FindingReported | ⏳ |
| cve_lookup | Assessment | CveLookupParser | FindingReported | ⏳ |
| execute_command | Utility | ExecuteCommandParser | ToolExecuted | ⏳ |

**Test Steps:**
1. ⏳ Execute each tool via Strike48 UI chat interface
2. ⏳ Verify tool output appears in chat
3. ⏳ Check that structured messages are created
4. ⏳ Confirm messages appear in appropriate sections (Targets, Findings, Credentials)
5. ⏳ Validate all fields are populated correctly

**Success Criteria:**
- Tool output rendered correctly in chat
- Structured data visible in engagement views
- No missing or malformed fields
- Relationships between entities preserved (e.g., Finding → Target)

---

## Phase 3: Performance Testing (Not Started)

### Objectives
- Benchmark parser performance with large datasets
- Identify bottlenecks in parsing pipeline
- Validate memory usage stays reasonable

### Test Cases

#### 3.1 Large Port Scan Results
- **Input:** 1000 hosts with 65,535 ports each
- **Expected:** < 5s parsing time, < 100MB memory
- **Status:** ⏳ Not started

#### 3.2 Bulk CVE Lookup
- **Input:** 100 products, 500 CVEs total
- **Expected:** < 10s parsing time, all findings created
- **Status:** ⏳ Not started

#### 3.3 WiFi Scan with Many Networks
- **Input:** 200+ WiFi networks with clients
- **Expected:** All high-value targets identified, < 3s parse time
- **Status:** ⏳ Not started

---

## Phase 4: Error Handling and Edge Cases (Not Started)

### Test Cases

#### 4.1 Malformed Tool Output
- Missing required fields
- Invalid data types
- Unexpected JSON structure
- **Expected:** Graceful fallback, logged warnings, partial data extraction

#### 4.2 Empty Results
- Tool succeeds but finds nothing
- **Expected:** Empty message array, no errors

#### 4.3 Partial Failures
- Some fields present, others missing
- **Expected:** Parse what's available, log missing fields

---

## Current Status Summary

| Phase | Status | Tests Passed | Tests Remaining |
|-------|--------|--------------|-----------------|
| Phase 1: Unit Testing | ✅ Complete | 85/85 (100%) | 0 |
| Phase 2: StrikeKit Integration | ⏳ In Progress | 0/10 (0%) | 10 |
| Phase 3: Performance Testing | ⏳ Not Started | 0/3 (0%) | 3 |
| Phase 4: Error Handling | ⏳ Not Started | 0/3 (0%) | 3 |

**Overall Progress:** 85/101 tests (84%)

---

## Next Actions

1. **Get connector approved in Strike48 UI** to proceed with Phase 2
2. **Execute port_scan tool** as first integration test
3. **Verify message appears in UI** with correct structure
4. **Iterate through remaining tools** in Critical Path
5. **Document any issues** or parser improvements needed
6. **Run performance tests** with large datasets
7. **Test error scenarios** and edge cases

---

## Notes

### Protobuf Dependency
- ✅ Installed `protobuf-compiler` version 3.21.12
- ✅ App compiles successfully with strike48-proto
- ✅ No protobuf build errors

### App Status
- Process: Running (PID varies)
- Connection: ✅ Connected to `wss://jt-demo-01.strike48.engineering`
- Registration: ✅ Matrix ID assigned
- Auth: ⏳ Waiting for UI approval
- Tools: 20 registered (traffic_capture excluded - no libpcap)

### Log Locations
- Live log: `/tmp/pentest-startup.log`
- App log: `/home/jtomek/tmp/pentest.log`
- Debug level: Enabled

---

**Last Updated:** 2026-03-12 17:15 UTC

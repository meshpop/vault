# sv-vault v2.0 — 프로젝트 현황

## 완료된 작업 (2026-03-14)

### 1. 암호화 엔진 (engine.py)
- AES-256-GCM 인증 암호화 (CBC 제거)
- Argon2id KDF (PBKDF2 제거) — 64MB 메모리, GPU 브루트포스 저항
- SV01 바이너리 포맷 (SPEC.md 참조)
- 파일/데이터/키 직접 암복호화

### 2. Shamir's Secret Sharing (keymanager.py)
- GF(2^8) polynomial 0x11D (primitive root order 255)
- N-of-K 분할/복원 — 5-of-3 기본
- 10/10 조합 전수 검증 완료
- 2개 share로는 복원 불가 (정보 이론적 보안) 확인

### 3. 분산 패스워드 관리 (vault.py)
- CRUD: add, get, update, delete, list, search
- 이중 잠금: 패스워드 기반 + Shamir 기반
- re-key: 마스터 키 교체 + 기존 share 무효화
- export/import: 암호화 이관
- 감사 로그: append-only JSONL

### 4. 전송 (transport.py)
- vssh 래퍼 — transport-agnostic (Wire/Tailscale/LAN)
- exec, put, get, broadcast, atomic_put
- SSH fallback 없음

### 5. 백업 (backup.py)
- 암호화 → .vault → 고정 타겟 업로드
- 복원, 검증, 감사 로그, 클린업

### 6. CLI (cli.py) — 22개 명령
- 시크릿: init, unlock, lock, add, get, update, delete, list, search
- 분산: distribute, collect, rekey
- 파일: encrypt, decrypt
- 백업: backup, restore, verify
- 기타: status, audit, export, import, info
- 키: key generate, key split, key recover

### 7. 패키징
- pyproject.toml — `pip install sv-vault`
- SV01 바이너리 포맷 스펙 (SPEC.md)

## 테스트 결과

| 파일 | 테스트 수 | 결과 |
|------|-----------|------|
| test_engine.py | 20 | PASS |
| test_keymanager.py | 18 | PASS |
| test_integration.py | 12 | PASS |
| test_vault.py | 30 | PASS |
| **합계** | **80** | **ALL PASS (1.56s)** |

## 라이브 검증 (<location> 없이 서울 8대)

- 5개 노드(d2,g1,g2,v1,v2)에 Shamir share 분산 저장
- 3개 노드에서만 회수 → 마스터 키 복원 → 7개 시크릿 복호화 성공
- 10가지 조합(5C3) 전수 검증 — 전부 성공
- 2개 share로 복원 시도 — 전부 실패 (보안 확인)
- 8대 동시 분산 명령 + 해시 무결성 확인
- s1 NAS(Synology) 백업 성공 — /volume1/NetBackup/sv-vault/

## 발견된 이슈 (해결 완료)

1. **GF(256) 다항식 버그** — 0x11B→0x11D 수정 (2의 order 51→255)
2. **백업 AAD 불일치** — source_hash를 AAD에서 context 문자열로 이동
3. **메타데이터 빈 파일** — _load_metadata에 빈 파일/JSON 에러 처리 추가

## 인프라 현황

| 노드 | 위치 | 상태 | 비고 |
|------|------|------|------|
| d2 | 서울 | ✅ 온라인 | Docker host |
| g1 | 서울 | ✅ 온라인 | GPU/Ollama |
| g2 | 서울 | ✅ 온라인 | App server |
| s1 | 서울 | ✅ 온라인 | NAS (vssh secret 미등록, 포트 열림) |
| m1 | 서울 | ✅ 온라인 | Local dev (Mac) |
| v1 | 클라우드 | ✅ 온라인 | Primary relay |
| v2 | 클라우드 | ✅ 온라인 | Secondary relay |
| v3 | 클라우드 | ✅ 온라인 | Backup relay |
| v4 | 미국 | ✅ 온라인 | US relay |
| d1 | <location> | ❌ 오프라인 | 전원 복구됨, 네트워크 미복구 |
| g3 | <location> | ❌ 오프라인 | 전원 복구됨, 네트워크 미복구 |
| g4 | <location> | ❌ 오프라인 | 전원 복구됨, 네트워크 미복구 |
| s2 | <location> | ❌ 오프라인 | NAS (NAS, 11TB) |
| n1 | <location> | ❌ 오프라인 | laptop 15 |

<location>: 전원 복구 확인. 공유기 재부팅 필요 (내일 직접 방문 예정).

## 다음 단계

### 즉시 (<location> 복구 후)
1. <location> 공유기 재부팅 → 네트워크 복구
2. s1 vssh secret 등록 (NAS)
3. s2 복구 확인 후 이중 백업 타겟 활성화
4. sv-vault distribute 실운영 (14대 전체)

### 단기
5. m1에 pip install → sv init 실운영 시작
6. Step News 파이프라인 복구 확인 (g3→v3)
7. SECUREVAULT_ARCHITECTURE.md 최종 업데이트

### 중기
8. vssh plaintext fallback 제거 (TLS/Noise)
9. gen-activity.py vssh 전환
10. 자동 재분배 — 노드 장애 감지 시 share 재분할
11. Web UI (선택)

## 설계 원칙 (불변)

- **룰 기반 전용** — AI/LLM이 보안 결정 안 함
- **패스워드 위치는 사람이 정함**
- **백업 타겟 고정: s1, s2**
- **Transport-agnostic** — vssh가 Wire/Tailscale/LAN 위에서 동작
- **SSH fallback 없음** — vssh가 안 되면 안 되는 것

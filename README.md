# ALEPH XDR-01 · Brute Force Defense

Wazuh 형식의 로그인 경보에서 MITRE ATT&CK **T1110** 공격 패턴을 탐지하고, 위험도에 따라 **block / alert / record**로 분류하는 XDR 보너스 과제입니다.

> **실행 범위:** 사전 제공된 ZTNA 판정기나 Wazuh 서버가 없어 **합성 Wazuh 경보 14건**과 **파일 기반 ZTNA 실습 판정기**로 모든 제작 단계를 재현했습니다. 실제 네트워크 차단이나 운영 Wazuh 서버 연동은 하지 않습니다. 배포 페이지는 정적 시뮬레이션 결과를 표시합니다.

## 실행 및 점검

```bash
npm run xdr:run -- brute-force
npm test
npm run build
```

- `xdr/brute-force/result.json`에 `counts`와 `normalBlocked`를 생성합니다.
- `xdr/alerts.log`에 **block/alert 경보를 한 줄씩** 남깁니다. 비밀번호나 토큰은 기록하지 않습니다.
- `xdr/temporary-deny.json`에 **경보 ID와 만료 시각이 있는 임시 IP 거부 규칙**을 만듭니다.
- `ztna/evaluate.mjs`가 **기존 `ztna/rules.json`을 읽으면서** XDR 임시 규칙까지 적용합니다. 원래 규칙은 수정하지 않습니다.
- 동일 시험 명령을 다시 실행하면 재현 가능한 결과로 파일을 갱신합니다. `now`는 실제 현재 시각이 아니라 **시험 기준 시각(2026-10-12T05:00:00Z)**입니다.
- GitHub Actions가 재생 → 테스트 → 재생 → 웹 빌드 → 변경 없는지 검사합니다.

## 요구사항 검증

| 제작 | 구현 파일 | 확인 방법 |
|---|---|---|
| 1 · 경보 읽기 | `xdr/brute-force/read-alerts.mjs` | 입력 14건 = 출력 14줄, 비밀값 마스킹 |
| 2 · 패턴 목록 | `xdr/brute-force/patterns.json` | MITRE T1110 근거가 모든 패턴에 한 줄씩 |
| 3 · 판단 모듈 | `xdr/brute-force/decide.mjs` | **import 없음, 파일/네트워크 I/O 없음**; 0.85↑ block, 0.50↑ alert, 그 미만 record |
| 4 · 알림/차단 | `xdr/brute-force/respond.mjs`, `ztna/evaluate.mjs` | 명확한 공격만 15분 임시 거부, 나머지 통과, 로그 생성 |
| 5 · 시험 경보 | `xdr/run.mjs`, `xdr/brute-force/result.json` | 14건 중 **block 4 / alert 3 / record 7**, 정상 오차단 **0건** |

### 직접 확인할 것

- 명확한 공격: `BF-001`~`BF-004` → **block**, ZTNA 임시 거부 규칙 4개
- 애매한 시도: `BF-005`~`BF-007` → **alert**만 기록, 거부 규칙 없음
- 정상·증거 부족: 그 외 7건 → **record**, 정상 이벤트 오차단 **0건**
- 임시 거부 규칙은 **15분 후 만료**, 정상 출발 주소는 기존 허용 정책을 따라 통과

## 구조

```text
xdr/
  fixtures/brute-force.json        # 시험용 Wazuh 형식 경보
  brute-force/
    read-alerts.mjs                # 확인 전용(판정기가 불러오지 않음)
    patterns.json
    decide.mjs                     # 심판 단독 불러오기 가능
    respond.mjs                    # 알림과 임시 차단 규칙 저장
    result.json
  alerts.log                       # 시험 경보 로그
  temporary-deny.json              # 임시 거부 규칙(실습용)
  run.mjs
ztna/
  rules.json                       # 기존 허용 정책: 변경하지 않음
  check.mjs                        # 순수 정책 평가
  evaluate.mjs                     # 기존 규칙 + 임시 거부 규칙 읽기
tests/brute-force.test.mjs
index.html                         # Vercel 공개 대시보드
```

## 판정의 범위와 한계

`decide(alert)`는 한 건의 이벤트만 받으므로 **해당 경보 안에 집계된 실패 수·시간 창·대상 계정 수**를 활용합니다. 계정에 실제 어떤 비밀번호가 시도됐는지는 수집하지 않습니다. 실무의 동적 IP, NAT 공유 사용자, Wazuh 경보 집계, 다중 서버 공유 정책 저장소 등은 별도 검증이 필요합니다.

배포는 Vercel 정적 호스팅이며 서버 함수, 비밀 환경변수, 실시간 트래픽 차단은 사용하지 않습니다.

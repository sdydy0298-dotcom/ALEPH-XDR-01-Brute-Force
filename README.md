# ALEPH XDR-01 · Brute Force Defense

MITRE ATT&CK **T1110** 기반 Wazuh 형식 로그인 경보 분석 및 ZTNA 임시 거부 규칙 연동 **독립형 실습**입니다.

> **중요:** 실제 Wazuh 서버, 기존 ZTNA 판정기 또는 공식 시험 경보는 제공되지 않았습니다. 본 저장소의 fixtures는 합성 경보이며, `ztna/check.mjs`는 실제 방화벽이 아닌 **로컬 실습용 정책 판정기**입니다. Vercel 대시보드는 정적 검증 결과를 표시합니다. 실제 트래픽 차단을 주장하지 않습니다.

## 검증 결과 (합성 시나리오)

- 전체 14건 / **block 4 · alert 3 · record 7**
- 정상 이벤트를 차단한 사례 **0건**
- 공격 주소는 임시 거부 규칙 후보를 생성하며 규칙마다 **경보 ID 및 15분 만료 시각**을 포함합니다.
- 실제 실행 시 `xdr/brute-force/result.json`이 갱신됩니다.

## 실행

```bash
npm run xdr:run -- brute-force
npm test
npm run build
```

Vercel은 저장소를 Import한 뒤 빌드 명령 `npm run build`, 출력 폴더 `public`을 사용합니다. 서버 함수와 환경변수는 필요하지 않습니다.

## 구성

| 파일 | 역할 |
|---|---|
| `xdr/fixtures/brute-force.json` | Wazuh 스타일 합성 로그인 경보 14건 |
| `xdr/brute-force/read-alerts.mjs` | 시간·출발 주소·계정·규칙 수준·설명만 읽는 검사기 |
| `xdr/brute-force/patterns.json` | T1110 근거·패턴·조건 |
| `xdr/brute-force/decide.mjs` | **외부 import 없이** `decide(alert)` 판단 |
| `xdr/brute-force/respond.mjs` | 임시 거부 규칙 및 알림 로그 연결 |
| `ztna/check.mjs` | 실습용 접근 통과/거부 판정 |
| `xdr/run.mjs` | 경보 재생 및 결과 생성 |
| `xdr/brute-force/result.json` | 판정별 건수와 오차단 확인 |
| `index.html` | 배포용 보안 관제 현황 대시보드 |

## 판정 기준

- `confidence >= 0.85`: **block** (출발 IP·명시적 인증 실패·짧은 기간의 반복 시도 등 증거 필요)
- `confidence >= 0.50`: **alert** (의심 정황이나 차단하기 불충분한 경우)
- 그 미만: **record** (정상 또는 근거 부족)
- `decide.mjs`는 순수 함수로 파일 입출력·패키지 의존성이 없습니다.
- `respond.mjs`가 별도 파일을 저장합니다. 정상/불확실 이벤트는 거부 규칙에 넣지 않습니다.
- 테스트에 쓰는 공개 IP는 RFC 5737 문서용 주소 대역이며, 실제 이용자 데이터가 아닙니다.

## 제한 사항

한 건의 경보만 받는 `decide(alert)`는 별도 히스토리를 유지할 수 없습니다. 따라서 여러 번의 실패를 판단하려면 **경보 안의 집계 데이터**(`data.summary`)가 있어야 합니다. 원본 사용자 비밀번호나 요청 본문을 수집하지 않습니다. 실무 투입 시 실제 Wazuh 수집, 정책 저장소, 안전한 임시 차단 해제, 승인 절차가 추가로 필요합니다.

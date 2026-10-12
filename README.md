# ALEPH XDR-01 · Brute Force Defense

2026-10-12 점검: 예전 제출은 임의로 만든 합성 경보 14건을 분석했으며 공식 예시의 경보 형식과 일치하지 않았습니다. 이번 버전은 **[ChoiTimo/aleph-defense-starter](https://github.com/ChoiTimo/aleph-defense-starter)의 실제 제공 예시**를 수정 없이 복사해 사용합니다.

> **중요:** 원본도 수업용 가상 Wazuh 형식입니다. 운영 Wazuh 서버와 실제 ZTNA 장비에 연결된 상태가 아니며, 여기서 BLOCK은 로컬 판정기 임시 거부 규칙을 뜻합니다.

## 제출 기준 재현

- 입력: `xdr/fixtures/brute-force.json` (원본의 `aleph.xdr.fixture.v1`, **28건**)
- 독립 판단: `xdr/brute-force/decide.mjs`, 외부 import / 파일 I/O 없음
- 공식 원본 실행기: `scripts/xdr-run.mjs` (원본의 `aleph.xdr.result.v1` 결과 계약 유지)
- 현재 테스트: **block 10 / alert 9 / record 9**, 정상 오차단 0건
- `xdr/alerts.log`에 BLOCK 및 ALERT 경보 19건 기록
- `xdr/temporary-deny.json`에 경보 번호·만료 시각을 가진 **15분 임시 규칙 10건**
- `ztna/evaluate.mjs`를 통해 정상 IP 허용과 위험 IP 임시 거부 검증
- 공개 대시보드에는 최종 검사 결과만 표시; 실제 트래픽 차단 기능이 아님

## 직접 실행

```bash
npm run xdr:run -- brute-force
npm test
npm run build
```

`npm run xdr:judge -- brute-force`는 교육용 원본 실행기만 단독으로 돌립니다. `npm run xdr:run`은 그 실행기 결과를 기반으로 로그와 시험 판정기 임시 규칙을 추가로 생성합니다.

## 소스 경로

| 경로 | 설명 |
|---|---|
| `xdr/fixtures/brute-force.json` | **원본 변경 없는** 수업용 Wazuh 경보 28건 |
| `xdr/brute-force/read-alerts.mjs` | 시각·출발 주소·계정·수준·설명만 추출 |
| `xdr/brute-force/patterns.json` | MITRE ATT&CK T1110 근거 패턴 |
| `xdr/brute-force/decide.mjs` | 인터넷 없이 단독 평가되는 `decide(alert)` |
| `xdr/brute-force/respond.mjs` | 알림 기록 및 임시 차단 규칙 연결 |
| `scripts/xdr-run.mjs` | 원본 공식 테스트 실행기 |
| `xdr/brute-force/result.json` | `aleph.xdr.result.v1` 규격의 판정 결과 |
| `ztna/evaluate.mjs` | 기존 정책 + 동적 차단 후보를 파일 기반으로 적용 |

원본 예시에는 정답표가 들어 있지 않습니다. 현재 카테고리 구분은 원본의 Wazuh 규칙 수준, MITRE T1110 태그, 설명·횟수·대상 계정 수를 근거로 한 자체 판정이며, **실제 심판 채점은 재제출 후 확인**해야 합니다.

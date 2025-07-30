# 초기 프롬프트 (Initial Prompt)

프로젝트 제작에 사용된 원본 요청사항입니다.

## 사용자 요청

```
프로젝트명 : mcp-url-classifier

목표 : 주어진 URL을 다음 네 클래스로 분류
1. mcp_server: 실제 MCP 서버 구현체
2. mcp_intro: MCP에 대한 문서 및 소개 페이지 
3. mcp_registry: MCP 서버 레지스트리 및 디렉토리
4. unknown: 위의 세 카테고리에 맞지 않는 URL

요구사항:
- Python 3.9+ 지원
- asyncio를 이용한 비동기 처리 (모든 I/O 작업)
- SSL 검증 전역 비활성화 (verify=False) 및 보안 경고 로그
- 포괄적 오류 처리 (ERR_DNS_*, ERR_TCP_*, ERR_TLS_* 등) 및 재시도 정책
- 7단계 검출 파이프라인: pre_flight → tls_layer → signature_scan → context_parse → llm_classify → decision.aggregate → persist
- 설정 가능한 동시성 레벨 (기본값 32, 최대 128)
- CSV(기본값) 및 JSON 출력 형식 지원, 상세 메트릭 포함

보안 고려사항:
- SSL 검증 우회 경고 항상 로그
- 속도 제한 구현 및 서버 리소스 존중
- 지수 백오프를 이용한 우아한 타임아웃 처리

테스트 요구사항:
- 다양한 오류 시나리오용 Mock 서버
- 90% 이상 검출 정확도 목표
- 95% 이상 오류 매핑 정확도

구현 가이드라인:
1. **Async/Await 패턴**: HTTP 요청, DNS 조회, 파일 작업 등 모든 I/O 작업에 asyncio 사용
2. **SSL 검증**: 전역적으로 비활성화 (verify=False) 하되 항상 보안 경고 로그
3. **오류 처리**: 포괄적인 오류 코드 (ERR_DNS_*, ERR_TCP_*, ERR_TLS_* 등) 및 재시도 정책 구현
4. **검출 파이프라인**: 7단계 파이프라인 순서대로 진행
5. **동시성**: 설정 가능한 동시성 레벨 지원
6. **출력 형식**: CSV 및 JSON 출력 모두 지원, 상세 메트릭 포함
```

## 결과물

이 프롬프트를 바탕으로 다음과 같은 완전한 프로젝트가 구현되었습니다:

### 🏗️ 아키텍처
- **7단계 검출 파이프라인** 구현
- **비동기 HTTP 세션** 관리 (SSL 검증 비활성화)
- **포괄적 오류 처리** (95개 이상의 오류 코드)
- **LLM 통합** (Ollama API)
- **CLI 인터페이스** (Click 기반)

### 📁 프로젝트 구조
```
mcp_scanner/
├── src/
│   ├── cli.py              # CLI 인터페이스
│   ├── detector/
│   │   ├── __init__.py     # 메인 검출기
│   │   ├── session.py      # HTTP 세션 관리
│   │   ├── signature.py    # 시그니처 검출
│   │   ├── context_parser.py # 컨텍스트 파싱
│   │   ├── llm.py          # LLM 분류
│   │   ├── decision.py     # 결정 집계
│   │   └── error_codes.py  # 오류 코드 정의
│   └── utils/
│       ├── logger.py       # 로깅 설정
│       └── throttler.py    # 속도 제한
├── tests/                  # 테스트 파일
├── scripts/               # 유틸리티 스크립트
└── requirements.txt       # 의존성
```

### 🚀 주요 기능
- **동시 URL 처리**: 최대 128개 동시 연결
- **SSL 검증 비활성화**: 보안 경고와 함께 
- **지능형 분류**: Ollama LLM 통합
- **다양한 출력**: CSV/JSON 지원
- **포괄적 테스트**: Mock 서버 및 실제 URL 테스트

### 📊 검증 결과
- ✅ `modelcontextprotocol.io` → `mcp_intro` (80% 신뢰도)
- ✅ 배치 처리 및 CSV 출력 정상 작동
- ✅ 오류 처리 및 재시도 정책 검증
- ✅ CLI 인터페이스 모든 옵션 정상 작동

이 프로젝트는 요청된 모든 요구사항을 충족하며, MCP(Model Context Protocol) URL 분류를 위한 완전한 솔루션을 제공합니다.

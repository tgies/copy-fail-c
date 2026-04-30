# Copy Fail (CVE-2026-31431) - C port

*[English (en)](README.md) ∙ [日本語 (ja)](README.ja.md) ∙ [简体中文 (zh-cn)](README.zh-cn.md) ∙ [한국어 (ko)](README.ko.md) ∙ [Русский (ru)](README.ru.md)*

Copy Fail 리눅스 로컬 권한 상승(LPE) 취약점(CVE-2026-31431)을 C 언어로 크로스 플랫폼에 맞게 재구현한 버전입니다. 이 취약점은 2026년 4월 29일 Theori / Xint에 의해 공개되었습니다. 전체 취약점 설명, 타임라인 및 Theori의 발견 과정에 대해서는 [copy.fail](https://copy.fail/)의 공식 분석 문서를 참조하세요.

공개적으로 배포된 개념 증명(PoC)은 732바이트 크기의 Python 스크립트입니다. 이 C 언어 포팅 버전은 프로젝트 소스에 아키텍처별 16진수 바이너리나 인라인 어셈블리를 포함하지 않고도, nolibc가 지원하는 모든 아키텍처로 컴파일 가능한 이식성 있는 C 언어로 동일한 익스플로잇을 구현할 수 있음을 보여줍니다.

이 포팅 버전의 작성자: Tony Gies <tony.gies@crashunited.com>
취약점 발견 및 최초 공개: Theori / Xint

## 저장소 구조

```
copy-fail-c/
├── exploit.c           드로퍼 (바이너리 변조 변형)
├── exploit-passwd.c    드로퍼 (/etc/passwd UID 변조 변형)
├── vulnerable.c        비파괴적 취약점 검사기
├── payload.c           드롭되는 본체 (setgid+setuid+execve sh)
├── utils.c, utils.h    공유 AF_ALG/splice 페이지 캐시 변조 원리
├── Makefile            빌드 오케스트레이션
├── nolibc/             torvalds/linux의 tools/include/nolibc에서 가져온 벤더 코드
└── README.md           이 파일 (설명서)
```

`make` 실행 후:

```
├── payload             작은 정적 ELF, 드로퍼에 바이트 형태로 내장됨
├── payload.o           `ld -r -b binary`를 통해 재배치 가능한 .o로 래핑된 페이로드
├── exploit             드로퍼, 바이너리 변조 변형
├── exploit-passwd      드로퍼, /etc/passwd UID 변조 변형
└── vulnerable          비파괴적 취약점 검사기
```

`exploit.c`는 대상 바이너리를 읽기 전용으로 연 다음, 내장된 페이로드의 4바이트 단위마다 AF_ALG를 통해 가짜 AEAD 복호화를 한 번 실행합니다. 이때 암호문 입력은 대상의 페이지 캐시 페이지에서 splice()를 통해 제공됩니다. authencesn 템플릿의 제자리(in-place) 최적화는 splice된 소스 페이지를 암호문 입력이자 평문 출력 대상으로 동시에 처리하므로, 인증 검증이 요청을 거부할 때쯤에는 이미 (실패할) 복호화가 페이지 캐시 페이지를 덮어쓴 상태가 됩니다. 4 * N번의 반복 후, 대상의 캐시된 이미지는 페이로드와 바이트 단위로 완전히 교체됩니다. 대상을 execve()하면 변조된 페이지가 로드됩니다. 디스크상의 inode는 여전히 setuid root이므로 커널은 root 권한을 부여하고 페이로드를 실행합니다.

`payload.c`는 단순하고 이식성 있는 C 코드입니다: `setgid(0); setuid(0); execve("/bin/sh", ...)`. nolibc는 `_start`, 시스템 콜 메커니즘, 그리고 아키텍처별 레지스터 조작을 제공합니다.

두 번째 변형인 `exploit-passwd.c`는 setuid 바이너리의 이미지 대신 /etc/passwd의 페이지 캐시 중 4바이트를 변조합니다. 내장된 페이로드가 필요하지 않으며 바이너리 변조 경로가 차단된 시스템에서도 작동하지만, 이로 인해 권한 상승(cashout)을 달성할 수 있는 공격 표면(attack surface)은 훨씬 좁아집니다.

`vulnerable.c`는 익스플로잇이 아닙니다. 문자열 `init`이 들어 있는 로컬 `testfile`을 생성한 후, 동일한 `patch_chunk()` 원리를 해당 파일의 페이지 캐시에 적용하여 바이트를 `vulnerable`로 덮어쓰려고 시도합니다. 읽어 들인 내용이 일치하면 실행 중인 커널은 CVE-2026-31431의 영향 범위 내에 있습니다. 디스크상의 inode는 변경되지 않습니다. `testfile`은 종료 시 제거되며, 페이지 캐시의 변조도 함께 사라집니다. 권한 없이 실행할 수 있습니다. 취약하면 종료 코드 100, 그렇지 않으면 0을 반환합니다.

## 빌드

기본 (호스트 아키텍처 네이티브):

```sh
make
```

aarch64 (또는 크로스 툴체인이 설치된 다른 리눅스 아키텍처)로 크로스 컴파일:

```sh
make CC=aarch64-linux-gnu-gcc LD=aarch64-linux-gnu-ld
```

함께 제공되는 nolibc가 지원하는 아키텍처(업스트림 기준): x86_64, i386, arm, aarch64, riscv32/64, mips, ppc, s390x, loongarch, m68k, sh, sparc. nolibc는 컴파일러의 아키텍처 매크로를 기반으로 분기하므로 올바른 `CC`/`LD`를 선택하는 것만으로 충분합니다.

빌드 요구 사항:

* C 컴파일러 (`cc`, `gcc` 또는 모든 크로스 변형)
* `ld -r -b binary`를 지원하는 링커 (binutils ld 및 lld 모두 지원)
* `linux/if_alg.h` 및 `<asm/unistd.h>`를 제공하는 커널 UAPI 헤더 (Debian/Ubuntu: `linux-libc-dev`, 크로스 변형: 일반적으로 크로스 툴체인 패키지에 의해 함께 설치됨)

외부 라이브러리 종속성이 없습니다. 페이로드는 nolibc에 대해 독립적(freestanding)으로 빌드되며, 드로퍼는 오직 `fprintf`와 `perror`를 위해 호스트 libc와 링크됩니다.

## 아키텍처 선택

코드를 이식성 있게 유지하고 페이로드 크기를 작게 유지하는 데 있어 툴체인의 3가지 작은 기능이 큰 역할을 합니다.

### nolibc

`nolibc/`는 커널에서 제공하는 작고 헤더로만 구성된 libc 대체품으로, torvalds/linux의 `tools/include/nolibc/`에서 가져왔습니다. 이는 `_start`, 이식성 있는 `syscall()` 매크로, 인라인 시스템 콜 래퍼를 제공하며, 아키텍처별 레지스터 규칙은 `nolibc/arch-*.h`에 인코딩되어 있습니다. `-nostdlib -static -ffreestanding -Inolibc` 옵션으로 페이로드를 빌드하면 glibc의 시작 코드, TLS 초기화 또는 스택 카나리 메커니즘을 포함하지 않고 커널을 직접 호출하는 아주 작은 정적 ELF가 생성됩니다. 결과적으로 x86_64에서는 약 1.7 KB, aarch64에서는 약 2.0 KB가 됩니다. 동일한 `payload.c`를 musl-static으로 링크하면 약 17 KB, glibc-static으로 링크하면 약 700 KB가 되는 것과 대조적입니다.

### 페이로드 내장을 위한 `ld -r -b binary`

Makefile은 `ld -r -b binary -o payload.o payload`를 통해 빌드된 `payload` ELF를 `payload.o`로 변환합니다. 링커는 입력 바이트를 재배치 가능한 목적 파일의 데이터 섹션으로 그대로 출력하며, 입력 파일 이름에서 세 가지 심볼을 합성합니다:

```
_binary_payload_start    첫 번째 페이로드 바이트의 주소
_binary_payload_end      마지막 페이로드 바이트의 바로 다음 주소
_binary_payload_size     바이트 단위 크기를 값으로 갖는 절대 심볼
```

`exploit.c`는 처음 두 개를 `extern const unsigned char[]`로 선언하고, `_binary_payload_end - _binary_payload_start`를 통해 크기를 계산합니다.

### `-Wl,-N` 및 엄격한 `max-page-size`

페이로드는 `-Wl,-N -Wl,-z,max-page-size=0x10` 옵션으로 정적 링크됩니다. 이는 `.text`/`.rodata`/`.data`를 커널 페이지 정렬인 세그먼트당 4 KB의 기본값 대신 16바이트 파일 정렬을 가지는 단일 LOAD 세그먼트로 병합합니다. 이로 인해 `ld`에서 "RWX permissions" 경고가 발생하지만 이는 단순한 정보일 뿐입니다. 단일 목적 프로그램인 페이로드의 런타임 메모리 보호는 중요하지 않기 때문입니다. 이 플래그가 없으면 동일한 코드가 x86_64에서 약 13 KB(대부분 세그먼트 간 0 패딩)로 링크되지만, 이 옵션을 사용하면 약 1.7 KB로 줄어듭니다.

## 변형 및 권한 상승(Cashout) 가능성

이 저장소는 AF_ALG/splice 페이지 캐시 변조 원리를 공유하면서 루트 실행 권한을 얻는 방식(cashout)이 다른 두 가지 익스플로잇 변형을 제공합니다. 이들의 신뢰성 프로필은 동일하지 않으며, 이러한 차이는 실제 위협 모델을 평가할 때 중요합니다.

### 바이너리 변조 변형 (`exploit`)

대상 setuid 바이너리의 페이지 캐시를 내장된 페이로드 바이트로 변조한 다음 해당 바이너리를 실행(exec)합니다. 커널은 바이너리의 디스크 상에 변경되지 않은 setuid 비트를 바탕으로 루트 권한을 부여하고, 손상된 메모리 이미지를 로드하여 페이로드를 실행합니다.

공격자가 시스템의 임의의 루트 setuid 바이너리에 대해 `open(target, O_RDONLY)`을 수행할 수 있는 환경이라면 어디서든 작동합니다. 제한된 읽기 권한 디렉토리 뒤에 setuid 바이너리를 두는 환경이나 setuid가 없는 시스템 설계에서는 대체로 차단됩니다.

### /etc/passwd UID 변조 변형 (`exploit-passwd`)

/etc/passwd의 페이지 캐시 4바이트를 변조하여 현재 실행 중인 사용자의 UID 필드를 "0000"으로 설정합니다. /etc/passwd는 모든 표준 리눅스 시스템에서 전역적으로 읽기 가능하므로, 이 *변조* 자체는 보편적으로 적용됩니다. 이를 루트 실행으로 연결하려면 루트 권한 프로세스가 getpwnam/getpwuid를 통해 사용자를 조회하고 교차 검증 없이 해당 uid를 기반으로 동작해야 합니다. 이러한 정보를 사용하는 프로세스는 많이 존재하지만, 대부분은 커널에서 본 호출 uid나 디스크 상의 파일 소유권과 방어적으로 교차 확인을 수행하므로 권한 상승 시도가 무력화됩니다.

#### 권한 상승 가능성 매트릭스

| 권한 상승 방법 | 사전 root 설정 필요 여부 | 비고 |
|---|---|---|
| WSL2 세션 생성 | 아니요 | WSL의 세션별 `setuid(getpwnam(default_user)->pw_uid)`는 검증을 수행하지 않습니다. 깔끔하게 작동합니다. |
| util-linux `su` | 아니요 | 호출자 식별 처리가 관대합니다. |
| shadow-utils `su` | 예 | 변조로 인해 실제 uid가 매핑되지 않아 `getpwuid(getuid())` 호출자 식별 검사가 실패합니다. |
| sshd (기본값 `StrictModes yes`) | 예 (StrictModes 비활성화 필요) | StrictModes는 홈 디렉토리가 root 또는 `pw->pw_uid` 소유여야 함을 요구합니다. 변조로 인해 pw_uid=0이 되지만, 디스크 상의 소유자는 원래 uid로 유지됩니다. 불일치로 인해 인증이 거부됩니다. |
| MTA 로컬 전송 (postfix, exim 등) | 변동적 | MDA의 홈 권한 검증에 따라 다릅니다. 각 MTA별로 테스트가 필요합니다. |

#### `su` 실패 후 다른 방법 시도 (Pivoting)

`exploit-passwd`는 변조 후 가장 단순한 권한 상승 방법으로 `su <user>`를 실행합니다. 이는 util-linux `su`에서는 작동하지만 shadow-utils `su`에서는 "Cannot determine your user name(사용자 이름을 확인할 수 없습니다)." 이라는 오류와 함께 실패합니다. 이 시점에서도 페이지 캐시 변조는 여전히 유지되므로, (예: 교차 검증 없이 getpwnam을 통해 사용자를 조회하는 데몬을 사용하는 등) 다른 권한 상승 방법으로 전환하는 것이 가능합니다. 테스트를 마친 후에는 root로 `echo 3 > /proc/sys/vm/drop_caches`를 실행하여 손상된 페이지 캐시를 지워주세요.

## 영향을 받는 커널

```
하한:    torvalds/linux 72548b093ee3   2017년 8월, v4.14
                                        (AF_ALG iov_iter 재작업.
                                         splice를 통해 AEAD 스캐터리스트(scatterlist)로
                                         파일 페이지를 쓸 수 있는 원리를 도입함)

상한:    torvalds/linux a664bf3d603d   2026년 4월, mainline
                                        (2017년의 algif_aead 제자리(in-place)
                                         최적화를 되돌림. 소스와 대상 스캐터리스트를
                                         분리하여 페이지 캐시 페이지가 더 이상
                                         기록 가능한 암호화 대상이 될 수 없도록 함)
```

이 기간 동안: 패치를 백포트(backport)하지 않은 모든 주요 배포판 커널. Ubuntu, RHEL, SUSE, Amazon Linux, Debian은 모두 취약점 공개 시점에 기본 클라우드 이미지 커널에서 취약한 것으로 확인되었습니다. 배포판 수준의 백포트는 공개 발표와 함께 2026년 4월 29일경부터 배포되기 시작했습니다. 대상 커널이 이 기간에 해당하는지 확인하려면 커널의 git 로그나 배포판의 변경 로그(changelog)에 `a664bf3d603d` (또는 해당 배포판 전용 백포트)가 존재하는지 확인하세요.

## 라이선스 및 크레딧

CVE-2026-31431 취약점 발견 및 최초 공개: Theori / Xint.
공식 분석 보고서: <https://copy.fail/>.

이 C 언어 포팅: Tony Gies <tony.gies@crashunited.com>

`nolibc/`: 리눅스 커널 트리에서 가져왔으며, LGPL-2.1-or-later 또는 MIT 이중 라이선스로 배포됩니다 (`nolibc/nolibc.h` 및 개별 파일의 SPDX 헤더 참조).

이 저장소의 드로퍼 및 페이로드 소스 코드는 의존하는 nolibc 트리와 동일한 LGPL-2.1-or-later 또는 MIT 이중 라이선스 조건에 따라 배포됩니다. 이는 누구나 이 전체 디렉토리를 자신의 작업에 쉽게 가져다 쓸 수 있도록 라이선스 호환성을 유지하기 위함입니다.

익스플로잇과 페이로드는 보안 연구 및 방어적 탐지 목적으로 공개되었습니다. 소유하지 않거나 테스트를 위한 명시적인 권한이 없는 시스템에 대해 이를 사용하는 것은 작성자가 아닌 전적으로 본인의 책임입니다.

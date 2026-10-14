# DJMAX-PPL

본인의 DJMAX RESPECT V 플레이 패턴 기록을 저장하는 도구입니다.

## 요구 사항

- Windows + 64비트 Python 3.10+
- **Steam 클라이언트 실행 중**
- DJMAX RESPECT V 설치

```bat
py -m pip install cryptography UnityPy
```

## 사용법

```bat
py main.py
py main.py "C:\Program Files (x86)\Steam\steamapps\common\DJMAX RESPECT V"
py main.py "C:\Games\DJMAX RESPECT V" -o "D:\output" --locale ja_JP
```

- 경로를 생략하면 Steam 라이브러리에서 자동으로 찾습니다.
- `-o`, `--out` : 결과 저장 폴더 (기본값: 실행한 폴더)
- `--locale` : 곡명 언어 (기본값: `ko_KR`, 그 외 `en_US`, `ja_JP`)

## 출력

실행한 폴더에 `play_pattern_list_<YYYYMMDD-HHMMSS>.json` 이 생성됩니다.

```json
{
  "patterns": [
    {
      "patternUid": 81883,
      "songId": 818,
      "songName": "Megingjord",
      "composer": "7SEQ / XeoN",
      "mode": "8B",
      "difficulty": "MX",
      "score": 881149,
      "scoreRate": 88.11,
      "allCombo": 0,
      "combo": 365,
      "djPower": 0.0,
      "plays": 4
    }
  ]
}
```

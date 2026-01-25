| Domain                  | Easy | Medium | Hard | Total | Website left |
| ----------------------- | ---- | ------ | ---- | ----- | ------------ |
| **Binary Exploitation** | 2    | 1      | 0    | 3     | 0            |
| **Coding**              | 1    | 4      | 0    | 5     | 0            |
| **Cryptography**        | 5    | 2      | 2    | 9     | 5 `dummycryptoscripts` |
| **Forensics**           | 6    | 0      | 0    | 6     | 5 `ctf_challenge 3,4,5,6,7` |
| **Pyjail**              | 0    | 1      | 2    | 3     | 0            |
| **Reverse Engineering** | 3    | 2      | 0    | 5     | 0            |
| **Web exploitation**    | 4    | 7      | 1    | 12    | 0            |
| **OSINT**               | 10   | 2      | 0    | 12    | 3 `ctf_challenge 1,10 , commit messages leak` |
| **Misc**                | 2    | 3      | 3    | 8     | 2 `dont read me , the last input` |

## Total = 63
## Website = 48(46 cuz 2 osint yet to be updated)


# CTF Challenge Port Mapping

**Complete reference for all challenge ports**  
**Last Updated:** 2026-01-26 :: 12:59 AM

---

## All Challenges with Ports

| External Port | Internal Port | Challenge Name        | Category            | Path                                    |
|---------------|---------------|-----------------------|---------------------|-----------------------------------------|
| 1337          | 1337          | cipher-prison         | Pyjail              | `pyjail/cipher-prison`                  |
| 1338          | 1338          | blacklist-hell        | Pyjail              | `pyjail/blacklist-hell`                 |
| 1339          | 1339          | upside-down           | Reverse Engineering | `reverse_engineering/Upside-down`       |
| 1340          | 1340          | has-to-echo           | Reverse Engineering | `reverse_engineering/has-to-echo`       |
| 2222          | 22            | missing_tools         | Misc                | `Misc/missing_tools`                    |
| 5001          | 5000          | robots-watching       | Web                 | `web_exploitation/robots-watching`      |
| 5002          | 5000          | cookie-recipe         | Web                 | `web_exploitation/cookie-recipe`        |
| 5003          | 5000          | curl-unfurl           | Web                 | `web_exploitation/curl-unfurl`          |
| 8001          | 8001          | caesars_pizza_menu    | Cryptography        | `cryptography/caesars_pizza_menu`       |
| 8002          | 8002          | license_checker       | Reverse Engineering | `reverse_engineering/license_checker`   |
| 8003          | 5000          | Time_window_Exposure  | Web                 | `web_exploitation/Time_window_Exposure` |
| 8004          | 8004          | pathfinding_puzzle    | Coding              | `coding/pathfinding_puzzle`             |
| 8005          | 8005          | tree_traversal_secret | Coding              | `coding/tree_traversal_secret`          |
| 8006          | 8006          | regex_master          | Coding              | `coding/regex_master`                   |
| 8007          | 8007          | secure_portal         | Web                 | `web_exploitation/secure_portal`        |
| 8008          | 8008          | auth_adventure        | Web                 | `web_exploitation/auth_adventure`       |
| 8009          | 8000          | flag_in_cache         | Web                 | `web_exploitation/flag_in_cache`        |
| 8010          | 8000          | nothing-works         | Web                 | `web_exploitation/nothing-works`        |
| 8011          | 8000          | overthinker           | Web                 | `web_exploitation/overthinker`          |
| 8012          | 8000          | plain-sight           | Web                 | `web_exploitation/plain-sight`          |
| 8013          | 8000          | stranger-things       | Web                 | `web_exploitation/stranger-things`      |
| 8014          | 8000          | wrong_password        | Web                 | `web_exploitation/wrong_password`       |
| 8015          | 8015          | Formality Breach      | Misc                | `Misc/Formality breach`                 |
| 8016          | 8000          | endgame-protocol      | Reverse Engineering | `reverse_engineering/endgame-protocol`  |
| 8017          | 80            | echo_chamber          | Misc                | `Misc/echo_chamber`                     |
| 8018          | 8018          | Math Chall            | Coding              | `/coding/MathChall`                     |
| 9001          | 9001          | overflow_academy      | Binary Exploitation | `binary_exploitation/overflow_academy`  |
| 9998          | 9999          | prison-break          | Pyjail              | `pyjail/prison_break`                   |
| 9999          | 9999          | menu_pwner            | Binary Exploitation | `binary_exploitation/menu_pwner`        |
| 42552         | 42552         | Conditions            | Reverse Engineering | ``reverse_engineering/Conditions`       |
| 54321         | 54321         | Number of Ones        | Coding              | `/coding/NumbersOfones`                 |



**Access URLs:**
- Pyjail challenges: `nc localhost <PORT>`
- Web/Coding/Crypto challenges: `http://localhost:<PORT>`
- Missing Tools (SSH): `ssh ctfplayer@localhost -p 2222` (password: `startwithbasics`)



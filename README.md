## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

### Using These Challenges

You are free to:
- ✅ Host these challenges in your own CTF
- ✅ Modify and adapt them for educational purposes
- ✅ Learn from the source code and solutions
- ✅ Share with attribution

Please give credit by linking back to this repository when using these challenges.





| Domain                  | Easy | Medium | Hard | Total | Website left                                  |
| ----------------------- | ---- | ------ | ---- | ----- | --------------------------------------------- |
| **Binary Exploitation** | 2    | 1      | 0    | 3     | 0                                             |
| **Coding**              | 1    | 4      | 0    | 5     | 0                                             |
| **Cryptography**        | 5    | 2      | 2    | 9     | 0                                             |
| **Forensics**           | 6    | 0      | 0    | 6     | 0                                             |
| **Pyjail**              | 0    | 1      | 2    | 3     | 0                                             |
| **Reverse Engineering** | 2    | 2      | 0    | 4     | 0                                             |
| **Web exploitation**    | 4    | 7      | 1    | 12    | 1 `flag in cache`                             |
| **OSINT**               | 8    | 2      | 0    | 10    | 4 `commit messages leak,pinpoint,github.digital` |
| **Misc**                | 2    | 3      | 3    | 8     | 0                                             |

## Total = 60

## Website = 59(+1 for warm up)

# CTF Challenge Port Mapping

**Complete reference for all challenge ports**  
**Last Updated:** 2026-01-26 :: 12:59 AM

---

## All Challenges with Ports & Production URLs

| Challenge Name        | Category            | EC2 Instance | Production URL                                                   | Dev Port | Path                                    |
| --------------------- | ------------------- | ------------ | ---------------------------------------------------------------- | -------- | --------------------------------------- |
| **CTFd Platform**     | Infrastructure      | EC2-1        | https://ctf.dscjssstuniv.in                                      | 9090     | N/A                                     |
| auth_adventure        | Web                 | EC2-1        | https://auth.ctf.dscjssstuniv.in                                 | 8008     | `web_exploitation/auth_adventure`       |
| cookie-recipe         | Web                 | EC2-1        | https://cookierecipe.ctf.dscjssstuniv.in                         | 5002     | `web_exploitation/cookie-recipe`        |
| curl-unfurl           | Web                 | EC2-1        | https://curlunfurl.ctf.dscjssstuniv.in                           | 5003     | `web_exploitation/curl-unfurl`          |
| flag_in_cache         | Web                 | EC2-1        | https://flagcache.ctf.dscjssstuniv.in                            | 8009     | `web_exploitation/flag_in_cache`        |
| nothing-works         | Web                 | EC2-1        | https://nothingworks.ctf.dscjssstuniv.in                         | 8010     | `web_exploitation/nothing-works`        |
| overthinker           | Web                 | EC2-1        | https://overthinker.ctf.dscjssstuniv.in                          | 8011     | `web_exploitation/overthinker`          |
| plain-sight           | Web                 | EC2-1        | https://plainsight.ctf.dscjssstuniv.in                           | 8012     | `web_exploitation/plain-sight`          |
| robots-watching       | Web                 | EC2-1        | https://robotswatching.ctf.dscjssstuniv.in                       | 5001     | `web_exploitation/robots-watching`      |
| secure_portal         | Web                 | EC2-1        | https://secureportal.ctf.dscjssstuniv.in                         | 8007     | `web_exploitation/secure_portal`        |
| stranger-things       | Web                 | EC2-1        | https://stranger.ctf.dscjssstuniv.in                             | 8013     | `web_exploitation/stranger-things`      |
| Time_window_Exposure  | Web                 | EC2-1        | https://timewindow.ctf.dscjssstuniv.in                           | 8003     | `web_exploitation/Time_window_Exposure` |
| wrong_password        | Web                 | EC2-1        | https://wrongpassword.ctf.dscjssstuniv.in                        | 8014     | `web_exploitation/wrong_password`       |
| caesars_pizza_menu    | Cryptography        | EC2-2        | https://caesar.challenges1.ctf.dscjssstuniv.in                   | 8001     | `cryptography/caesars_pizza_menu`       |
| pathfinding_puzzle    | Coding              | EC2-2        | nc pathfinding.challenges1.ctf.dscjssstuniv.in 8004                          | 8004     | `coding/pathfinding_puzzle`             |
| regex_master          | Coding              | EC2-2        | nc regex.challenges1.ctf.dscjssstuniv.in 8006                          | 8006     | `coding/regex_master`                   |
| tree_traversal_secret | Coding              | EC2-2        | nc tree.challenges1.ctf.dscjssstuniv.in 8005                          | 8005     | `coding/tree_traversal_secret`          |
| Number of Ones        | Coding              | EC2-2        | nc numbers.challenges1.ctf.dscjssstuniv.in 54321                         | 54321    | `coding/NumberOfones/src`               |
| Math Chall            | Coding              | EC2-2        | nc math.challenges1.ctf.dscjssstuniv.in 8018                          | 8018     | `coding/MathChall`                      |
| endgame-protocol      | Reverse Engineering | EC2-2        | https://endgame.challenges1.ctf.dscjssstuniv.in                  | 8016     | `reverse_engineering/endgame-protocol`  |
| echo_chamber          | Misc                | EC2-2        | https://echochamber.challenges1.ctf.dscjssstuniv.in              | 8017     | `Misc/echo_chamber`                     |
| Formality Breach      | Misc                | EC2-2        | https://formalitybreach.challenges1.ctf.dscjssstuniv.in          | 8015     | `Misc/Formality_breach`                 |
| menu_pwner            | Binary Exploitation | EC2-3        | nc menupwner.challenges2.ctf.dscjssstuniv.in 9999                | 9999     | `binary_exploitation/menu_pwner`        |
| overflow_academy      | Binary Exploitation | EC2-3        | nc overflow.challenges2.ctf.dscjssstuniv.in 9001                 | 9001     | `binary_exploitation/overflow_academy`  |
| upside-down           | Reverse Engineering | EC2-3        | nc upsidedown.challenges2.ctf.dscjssstuniv.in 1339               | 1339     | `reverse_engineering/Upside-down`       |
| has-to-echo           | Reverse Engineering | EC2-3        | nc hastoecho.challenges2.ctf.dscjssstuniv.in 1340                | 1340     | `reverse_engineering/has-to-echo`       |
| Conditions            | Reverse Engineering | EC2-3        | https://conditions.challenges2.ctf.dscjssstuniv.in               | 42552    | `reverse_engineering/Conditions`        |
| cipher-prison         | Pyjail              | EC2-3        | nc cipherprison.challenges2.ctf.dscjssstuniv.in 1337             | 1337     | `pyjail/cipher-prison`                  |
| prison-break          | Pyjail              | EC2-3        | nc prisonbreak.challenges2.ctf.dscjssstuniv.in 9999              | 9998     | `pyjail/prison_break`                   |
| blacklist-hell        | Pyjail              | EC2-3        | nc blacklisthell.challenges2.ctf.dscjssstuniv.in 1338            | 1338     | `pyjail/blacklist-hell`                 |
| missing_tools         | Misc                | EC2-3        | ssh ctf@missingtools.challenges2.ctf.dscjssstuniv.in -p 2222     | 2222     | `Misc/missing_tools`                    |

---

## Infrastructure Summary

- **Total Challenges Deployed:** 31 (across 3 EC2 instances)
- **EC2-1:** Core platform (CTFd, MariaDB, Redis) + 12 Web challenges
- **EC2-2:** 5 Coding + 1 Crypto + 2 Reverse + 2 Misc (10 total)
- **EC2-3:** 2 PWN + 3 Reverse + 3 Pyjail + 1 Misc (9 total)
- **All services secured with Traefik + Let's Encrypt HTTPS**

See [ARCHITECTURE.md](ARCHITECTURE.md) for deployment details.

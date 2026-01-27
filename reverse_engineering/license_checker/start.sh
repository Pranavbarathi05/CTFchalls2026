#!/bin/bash
socat TCP-LISTEN:8002,reuseaddr,fork EXEC:"timeout 30 ./license_checker",pty,stderr,setsid,sigint,sane
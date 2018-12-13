#!/bin/sh

ps -ef | grep manager | grep -v grep | awk '{print $2}' | xargs kill

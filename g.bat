@echo off
echo git add .

git add .

rem echo Git pushed a dummy file for CI Demo
echo.
echo git commit -m "Initial Commint..."
git commit -m "Initial Commint..."
echo git branch -M main
REM Ensure branch is main
git branch -M main
echo git remote add origin https://github.com/luckyjoy/gemini_chatbot.git 
git remote add origin https://github.com/luckyjoy/gemini_chatbot.git 

echo git push origin main
git push origin main

echo Done.


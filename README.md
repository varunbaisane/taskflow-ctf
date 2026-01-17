# 🚩 TaskFlow CTF Challenges

This repository contains the source code for a vulnerable **TaskFlow CTF** web application built using Flask (Python) and designed to be deployed serverlessly on Vercel for the *SequriQuest*, CTF event conducted by Axios, IIIT Lucknow for first-year BTech students.

The application contains *6 distinct web vulnerabilities* intended under a 36-hour CTF event. Your goal is to explore the application, identify security flaws, and exploit them to capture the flags.

### 🎯 Target Environment

The application is a standard web app with user logins, a dashboard for managing tasks, an admin panel, and some auxiliary tools.

* **Tech Stack:** Python (Flask), Jinja2 templates, Tailwind CSS.
* **Deployment:** Vercel Serverless Functions (stateless environment).


## The Challenges

Below are the 6 challenges hidden within the TaskFlow application. Good luck!

### 1. TaskFlow: Control Urself

### Description
 The developer dave seems careless and he comments on us. Can you find the flag they left during development?!?!

Website: [https://taskflow-ctf.vercel.app/](https://taskflow-ctf.vercel.app/)


👉 **[View Writeup](./writeup/writeup.md)**

---

### 2. TaskFlow: Mr. Roboto

### Description
Search engines are great, but sometimes we don't want them looking at our secret files.

Website: [https://taskflow-ctf.vercel.app/](https://taskflow-ctf.vercel.app/)

👉 **[View Writeup](./writeup/writeup.md)**

---

### 3. TaskFlow: Admin Loves Cookies

### Description
I can log in as a user, but the Admin panel says `Access Denied`.

Website: [https://taskflow-ctf.vercel.app/admin](https://taskflow-ctf.vercel.app/admin)

👉 **[View Writeup](./writeup/writeup.md)**

---

### 4. TaskFlow: Not Found

### Description
The 404 page echoes your input. Maybe it’s vulnerable?*

👉 **[View Writeup](./writeup/writeup.md)**

---

### 5. Challenge: Peeping

### Description

Try 

`user: bob`

`password: bob123`

Do you think, something in the url looks fishy🐠???

Website: [https://taskflow-ctf.vercel.app/](https://taskflow-ctf.vercel.app/)

👉 **[View Writeup](./writeup/writeup.md)**

---

### 6. Challenge: Calculated Risk

### Description
We added a new "Safe" calculator. It has a strict firewall to prevent hackers from stealing our secrets.

Website: [https://taskflow-ctf.vercel.app/calculator](https://taskflow-ctf.vercel.app/calculator)

👉 **[View Writeup](./writeup/writeup.md)**

---


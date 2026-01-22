# Formality Breach

## Challenge Description

You've been given access to what appears to be a standard customer feedback form. It accepts responses, allows editing, and seems to work perfectly. But is everything as it seems?

**Hint:** Not all analytics are created equal...

---

## Challenge Info

- **Category:** Misc
- **Difficulty:** Easy
- **Port:** 8015
- **Flag Location:** The flag is in the real form analytics

---

## How to Play

1. Start the challenge:
   ```bash
   cd "Misc/Formality breach"
   sudo docker-compose up -d
   ```

2. Access the form at: http://localhost:8015

3. Submit responses, edit them, explore the application...

4. Find the hidden analytics page!

---

## Learning Objectives

- Understanding web application reconnaissance
- URL manipulation and discovery
- Recognizing fake/frontend-only applications
- Google Forms analytics exposure

---

## Hints

<details>
<summary>Hint 1: Where would you normally see analytics?</summary>
Think about what URL parameters or paths Google Forms uses...
</details>

<details>
<summary>Hint 2: What's suspicious about this form?</summary>
You can edit your responses infinitely, and there's no real backend storage...
</details>

<details>
<summary>Hint 3: Try common paths</summary>
What happens when you add `/viewanalytics` to the URL?
</details>

---

## Solution

The challenge is a fake Google Forms clone that:
1. Accepts any responses without actually storing them
2. Allows infinite edits (since nothing is really saved)
3. Has a special route at `/viewanalytics` that redirects to the real Google Form

**Steps to solve:**
1. Notice the form accepts everything and allows unlimited edits
2. Try accessing common Google Forms paths like `/viewanalytics`
3. Get redirected to: https://docs.google.com/forms/d/1Vczctm8LlOieYFcq3OYBJEkTGUwIl8nqsRu9wSh22kc/viewanalytics
4. View the real form's analytics to find the flag

**Flag:** Located in the actual Google Form analytics page

---

## Technical Details

### Application Structure
- Flask-based fake form application
- No persistent storage (all responses in memory)
- Session-based response tracking
- Redirect endpoint for analytics

### Key Vulnerabilities
- Frontend-only validation
- No actual data persistence
- Exposed analytics redirect
- Unlimited response editing (red flag)

### Real-World Context
This simulates:
- Improperly secured form analytics
- Public Google Form exposure
- Information disclosure via analytics
- Fake/honeypot applications

---

## Files

- `app.py` - Main Flask application
- `templates/form.html` - Main form page
- `templates/submitted.html` - Submission confirmation
- `templates/edit.html` - Response editing page
- `Dockerfile` - Container configuration
- `docker-compose.yml` - Deployment configuration

---

## Deployment

```bash
# Start
cd "Misc/Formality breach"
sudo docker-compose up -d

# Check logs
sudo docker-compose logs -f

# Stop
sudo docker-compose down
```

Access at: http://localhost:8015

---

## Challenge Author Notes

This challenge teaches players to:
1. Recognize suspicious behavior (unlimited edits, instant responses)
2. Explore common web paths and endpoints
3. Understand how Google Forms analytics can expose data
4. Think critically about frontend vs backend validation

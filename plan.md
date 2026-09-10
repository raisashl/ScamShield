# ScamShield --- Project Plan

## 1. Project Overview

**Project Name:** ScamShield\
**Project Type:** AI-powered web application\
**Goal:** Detect potentially fraudulent or suspicious SMS, WhatsApp
messages, emails, and URLs and provide an understandable risk
assessment.

ScamShield will analyze user-provided text or links and classify them as
**Low Risk, Medium Risk, or High Risk**, while explaining the reasons
behind the result and giving safe-action recommendations.

------------------------------------------------------------------------

## 2. Problem Statement

Online scams are becoming increasingly common through SMS, WhatsApp,
email, and malicious links. Many users cannot easily identify whether a
message or URL is genuine or fraudulent.

ScamShield aims to provide a simple tool that helps users identify
suspicious content before they click links, share personal information,
or make payments.

------------------------------------------------------------------------

## 3. Main Objectives

-   Detect suspicious or scam-like messages.
-   Analyze URLs for potentially dangerous characteristics.
-   Assign a risk level and risk score.
-   Explain why the content is considered suspicious.
-   Provide practical safety recommendations.
-   Build a responsive and user-friendly interface.
-   Demonstrate the use of software engineering principles together with
    AI/NLP.

------------------------------------------------------------------------

## 4. Core Features

### Phase 1 --- Basic Application

-   Text/message input.
-   URL input.
-   Analyze button.
-   Risk result screen.
-   Responsive UI.

### Phase 2 --- Rule-Based Detection

Detect common scam indicators such as: - Urgent or threatening
language. - Requests for OTP, PIN, password, or banking details. -
Suspicious payment requests. - Fake prize/reward claims. -
Account-blocking or verification threats. - Suspicious URL patterns.

### Phase 3 --- AI/NLP Detection

-   Collect and prepare a labeled scam/legitimate dataset.
-   Text preprocessing.
-   Feature extraction.
-   Train a machine-learning/NLP classification model.
-   Evaluate accuracy, precision, recall, and F1-score.
-   Save the trained model.

### Phase 4 --- Combined Risk Engine

Combine: - Rule-based score. - ML/NLP prediction. - URL analysis.

Generate: - Risk level: LOW / MEDIUM / HIGH. - Risk percentage/score. -
Main reasons for the classification. - Recommended action.

### Phase 5 --- Finalization

-   Improve UI/UX.
-   Add error handling.
-   Test different scam examples.
-   Document architecture and workflow.
-   Prepare screenshots.
-   Prepare project report.
-   Prepare PPT and viva questions.

------------------------------------------------------------------------

## 5. Proposed Technology Stack

### Frontend

-   HTML
-   CSS
-   JavaScript
-   React.js (optional upgrade)

### Backend

-   Python
-   FastAPI

### AI/ML

-   Python
-   scikit-learn
-   NLP techniques
-   Optional advanced model: Transformer/BERT-based classifier

### Database

-   PostgreSQL

### Development Tools

-   VS Code
-   Git
-   GitHub
-   Postman

### Deployment --- Later

-   Render / Railway / AWS

------------------------------------------------------------------------

## 6. System Workflow

``` text
User Input
   |
   v
Message / URL
   |
   v
Preprocessing
   |
   +--------------------+
   |                    |
   v                    v
Rule Analysis       AI/NLP Model
   |                    |
   +---------+----------+
             |
             v
       Risk Score Engine
             |
             v
     LOW / MEDIUM / HIGH
             |
             v
     Reasons + Safety Tips
```

------------------------------------------------------------------------

## 7. Example

### Input

> Your bank account will be blocked today. Click here to verify your
> account: suspicious-example.com

### Expected Output

**Risk Level:** HIGH\
**Risk Score:** 87%

**Reasons:** - Uses urgent/threatening language. - Requests account
verification. - Contains a suspicious-looking URL. - Attempts to create
fear and immediate action.

**Recommendation:** Do not click the link. Do not provide OTP, password,
PIN, card details, or other sensitive information. Verify the message
through the organization's official website or app.

------------------------------------------------------------------------

## 8. Database Design --- Initial

### Users

-   user_id
-   name
-   email
-   password_hash
-   created_at

### Scans

-   scan_id
-   user_id
-   input_type
-   input_text
-   risk_score
-   risk_level
-   detected_reasons
-   created_at

The database can be simplified or introduced later depending on project
scope.

------------------------------------------------------------------------

## 9. API Plan

### POST /analyze

Accepts a message or URL and returns the analysis result.

### GET /health

Checks whether the backend is running.

### GET /history

Returns previous scans if user history is implemented.

------------------------------------------------------------------------

## 10. Testing Plan

### Functional Testing

-   Valid message input.
-   Empty input.
-   Very long input.
-   Normal/legitimate messages.
-   Known scam-like messages.
-   Suspicious URLs.
-   Invalid URLs.

### AI Model Testing

-   Accuracy.
-   Precision.
-   Recall.
-   F1-score.
-   Confusion matrix.

### UI Testing

-   Mobile responsiveness.
-   Desktop responsiveness.
-   Different screen sizes.
-   Error messages.
-   Loading states.

### Security Testing

-   Input validation.
-   API validation.
-   Password hashing if authentication is implemented.
-   Protection against malicious input.

------------------------------------------------------------------------

## 11. Development Milestones

### Milestone 1

Set up project structure and GitHub repository.

### Milestone 2

Build frontend with message and URL input.

### Milestone 3

Implement basic rule-based scam detection.

### Milestone 4

Build FastAPI backend and connect frontend.

### Milestone 5

Add database/history if required.

### Milestone 6

Train and integrate the NLP/ML model.

### Milestone 7

Combine rule-based and AI predictions.

### Milestone 8

Test, improve UI, fix bugs, and prepare documentation.

### Milestone 9

Deploy the application and prepare the final demonstration.

------------------------------------------------------------------------

## 12. Future Enhancements

-   Browser extension.
-   WhatsApp/email integration where legally and technically
    appropriate.
-   Multilingual scam detection.
-   Voice scam detection.
-   QR-code/link analysis.
-   Real-time threat intelligence.
-   Explainable AI dashboard.
-   Mobile application.
-   Community-based scam reporting.

------------------------------------------------------------------------

## 13. Final Project Goal

The final version of ScamShield should demonstrate that a user can
submit suspicious content and receive a fast, understandable, and
actionable risk assessment.

The project should showcase:

**Software Engineering + Web Development + Backend Development +
Database + AI/NLP + Security Awareness**

------------------------------------------------------------------------

## 14. Important Scope Rule

Start simple.

Do **not** begin with advanced AI, databases, deployment, or complex
security features.

Build in this order:

**UI → Rule Engine → Backend → ML/NLP → Combined Risk Engine → Testing →
Deployment**

This keeps the project achievable while still making it strong enough
for a BCA portfolio and software-engineering interviews.

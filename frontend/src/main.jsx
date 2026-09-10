import React, { useEffect, useMemo, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';

import {
  ShieldCheck,
  ScanSearch,
  Link2,
  MessageSquareText,
  AlertTriangle,
  CheckCircle2,
  Copy,
  History,
  ArrowRight,
  LockKeyhole,
  ExternalLink,
  Info,
  Sparkles,
  Upload,
  FileText
} from 'lucide-react';

import './styles.css';

const API_URL = 'http://10.1.30.204:8000';

const HISTORY_KEY = 'scamshield_history';

const examples = [
  {
    label: 'Bank alert',
    text: 'Your bank account will be blocked today. Verify immediately at http://secure-account-check.example/login to avoid suspension.'
  },
  {
    label: 'Prize scam',
    text: 'Congratulations! You won a cash prize of ₹50,000. Pay a small processing fee now to claim your reward.'
  },
  {
    label: 'Normal message',
    text: 'Hey, the meeting is moved to 4 PM. Please bring the project report.'
  }
];


/* =========================================================
   FORMAT BACKEND RESULT
========================================================= */

function formatResult(data) {

  const score = Number(
    data.overall_risk ?? data.score ?? 0
  );

  const rawLevel = (
    data.risk_level ??
    data.level ??
    'LOW'
  ).toUpperCase();

  const level = rawLevel
    .replace(/\s+RISK\s+RISK$/i, ' RISK')
    .replace(/\s+RISK$/i, '');

  let reasons = [];


  /* -------------------------------------------------------
     BACKEND PATTERNS
  ------------------------------------------------------- */

  if (Array.isArray(data.patterns)) {
    reasons.push(...data.patterns);
  }


  /* -------------------------------------------------------
     SECTION FLAGS
  ------------------------------------------------------- */

  if (Array.isArray(data.sections)) {

    data.sections.forEach((section) => {

      if (Array.isArray(section.flags)) {
        reasons.push(...section.flags);
      }

    });

  }


  /* -------------------------------------------------------
     URL WARNINGS
  ------------------------------------------------------- */

  let urlFlags = [];


  if (Array.isArray(data.url_flags)) {
    urlFlags.push(...data.url_flags);
  }


  if (Array.isArray(data.sections)) {

    data.sections.forEach((section) => {

      if (Array.isArray(section.url_flags)) {
        urlFlags.push(...section.url_flags);
      }

    });

  }


  urlFlags = [...new Set(urlFlags)];


  /* -------------------------------------------------------
     REMOVE DUPLICATE REASONS
  ------------------------------------------------------- */

  reasons = [...new Set(reasons)];


  /* -------------------------------------------------------
     FALLBACK REASONS
  ------------------------------------------------------- */

  if (!reasons.length) {

    if (level === 'HIGH') {

      reasons = [
        'The model detected strong suspicious patterns'
      ];

    } else if (level === 'MEDIUM') {

      reasons = [
        'The model detected some suspicious patterns'
      ];

    } else {

      reasons = [
        'No significant scam indicators were detected'
      ];

    }

  }


  /* -------------------------------------------------------
     SAFETY RECOMMENDATION
  ------------------------------------------------------- */

  let safe;

  if (level === 'HIGH') {

    safe =
      'Do not click links, send money, or share sensitive information. Verify the message through an official channel.';

  } else if (level === 'MEDIUM') {

    safe =
      'Be cautious. Verify the sender, website, and request independently before taking action.';

  } else {

    safe =
      'Looks relatively low-risk, but still verify unexpected requests before responding.';

  }


  return {

    score: Math.round(score * 100) / 100,

    level,

    reasons: reasons.slice(0, 5),

    urlFlags: urlFlags.slice(0, 5),

    safe

  };

}


/* =========================================================
   MAIN APP
========================================================= */

function App() {

  const [input, setInput] = useState('');

  const [result, setResult] = useState(null);

  const [history, setHistory] = useState([]);

  const [copied, setCopied] = useState(false);

  const [tab, setTab] = useState('analyze');

  const [loading, setLoading] = useState(false);

  const [error, setError] = useState('');


  const fileInputRef = useRef(null);


  /* =======================================================
     LOAD HISTORY FROM BROWSER STORAGE
  ======================================================= */

  useEffect(() => {

    try {

      const savedHistory =
        localStorage.getItem(HISTORY_KEY);

      if (savedHistory) {

        const parsed =
          JSON.parse(savedHistory);

        if (Array.isArray(parsed)) {
          setHistory(parsed);
        }

      }

    } catch (err) {

      console.error(
        'Could not load ScamShield history:',
        err
      );

    }

  }, []);


  /* =======================================================
     SAVE HISTORY TO BROWSER STORAGE
  ======================================================= */

  useEffect(() => {

    try {

      localStorage.setItem(
        HISTORY_KEY,
        JSON.stringify(history)
      );

    } catch (err) {

      console.error(
        'Could not save ScamShield history:',
        err
      );

    }

  }, [history]);


  /* -------------------------------------------------------
     History statistics
  ------------------------------------------------------- */

  const stats = useMemo(
    () => ({
      scans: history.length,

      high: history.filter(
        (x) => x.level === 'HIGH'
      ).length
    }),
    [history]
  );


  /* =======================================================
     SAVE RESULT TO HISTORY
  ======================================================= */

  function saveHistory(text, r) {

    const newEntry = {

      id: Date.now(),

      text,

      ...r,

      time: new Date().toLocaleTimeString([], {
        hour: '2-digit',
        minute: '2-digit'
      }),

      date: new Date().toLocaleDateString([], {
        day: '2-digit',
        month: 'short',
        year: 'numeric'
      })

    };


    setHistory((h) => [

      newEntry,

      ...h

    ].slice(0, 8));

  }


  /* =======================================================
     TEXT ANALYSIS
  ======================================================= */

  async function run() {

    if (!input.trim() || loading) return;


    setLoading(true);

    setError('');

    setResult(null);


    try {

      const response = await fetch(
        `${API_URL}/analyze`,
        {
          method: 'POST',

          headers: {
            'Content-Type': 'application/json'
          },

          body: JSON.stringify({
            text: input.trim()
          })

        }
      );


      const data = await response.json();


      if (!response.ok || data.error) {

        throw new Error(
          data.error || 'Analysis failed'
        );

      }


      const r = formatResult(data);


      setResult(r);


      saveHistory(
        input.trim(),
        r
      );


    } catch (err) {

      console.error(err);


      setError(
        'Could not connect to ScamShield backend. Make sure the FastAPI server is running on port 8000.'
      );


    } finally {

      setLoading(false);

    }

  }


  /* =======================================================
     PDF ANALYSIS
  ======================================================= */

  async function handlePDF(event) {

    const file =
      event.target.files?.[0];


    if (!file) return;


    if (
      file.type !== 'application/pdf'
    ) {

      setError(
        'Please select a PDF file.'
      );

      return;

    }


    setLoading(true);

    setError('');

    setResult(null);


    try {

      const formData =
        new FormData();


      formData.append(
        'file',
        file
      );


      const response =
        await fetch(
          `${API_URL}/analyze-pdf`,
          {
            method: 'POST',
            body: formData
          }
        );


      const data =
        await response.json();


      if (
        !response.ok ||
        data.error
      ) {

        throw new Error(
          data.error ||
          'PDF analysis failed'
        );

      }


      const r =
        formatResult(data);


      setResult(r);


      saveHistory(
        `PDF: ${file.name}`,
        r
      );


    } catch (err) {

      console.error(err);


      setError(
        err.message ||
        'Could not analyze the PDF.'
      );


    } finally {

      setLoading(false);

      event.target.value = '';

    }

  }


  /* =======================================================
     COPY RESULT
  ======================================================= */

  async function copy() {

    if (!result) return;


    await navigator.clipboard?.writeText(

      `${result.level} RISK — ${result.score}%\n` +

      `${result.reasons.join('\n')}` +

      (
        result.urlFlags?.length
          ? `\n\nURL security checks:\n${result.urlFlags.join('\n')}`
          : ''
      )

    );


    setCopied(true);


    setTimeout(() => {

      setCopied(false);

    }, 1200);

  }


  /* =======================================================
     UI
  ======================================================= */

  return (

    <div className="app">


      {/* =================================================
          NAVIGATION
      ================================================= */}

      <nav className="nav">


        <div className="brand">

          <span className="logo">

            <ShieldCheck />

          </span>


          <span>

            Scam<span>Shield</span>

          </span>

        </div>


        <div className="navlinks">


          <button

            className={
              tab === 'analyze'
                ? 'active'
                : ''
            }

            onClick={() =>
              setTab('analyze')
            }

          >

            Analyzer

          </button>


          <button

            className={
              tab === 'history'
                ? 'active'
                : ''
            }

            onClick={() =>
              setTab('history')
            }

          >

            History <b>{stats.scans}</b>

          </button>


        </div>


        <div className="secure">

          <LockKeyhole size={15} />

          Privacy-first

        </div>

      </nav>


      {/* =================================================
          ANALYZER TAB
      ================================================= */}

      {tab === 'analyze' ? (

        <main>


          {/* =============================================
              HERO
          ============================================= */}

          <section className="hero">


            <div className="pill">

              <Sparkles size={14} />

              ML-powered risk analysis

            </div>


            <h1>

              Pause. <em>Check.</em> Stay safe.

            </h1>


            <p>

              Analyze suspicious messages,
              links, and employment documents
              using ScamShield's machine-learning
              model and scam detection rules.

            </p>

          </section>


          {/* =============================================
              WORKSPACE
          ============================================= */}

          <section className="workspace">


            {/* ===========================================
                INPUT PANEL
            =========================================== */}

            <div className="panel inputpanel">


              <div className="panelhead">


                <div>

                  <small>
                    01 / INPUT
                  </small>

                  <h2>
                    What did you receive?
                  </h2>

                </div>


                <span className="counter">

                  {input.length}/2000

                </span>

              </div>


              {/* TEXT INPUT */}

              <div className="inputwrap">


                <textarea

                  maxLength="2000"

                  value={input}

                  onChange={(e) =>
                    setInput(e.target.value)
                  }

                  placeholder="Paste an SMS, WhatsApp message, email text, or URL here…"

                />


                <div className="inputicons">

                  <MessageSquareText
                    size={18}
                  />

                  <Link2
                    size={18}
                  />

                </div>

              </div>


              {/* EXAMPLES */}

              <div className="examples">


                <span>
                  Try an example:
                </span>


                {examples.map((e) => (

                  <button

                    key={e.label}

                    onClick={() =>
                      setInput(e.text)
                    }

                  >

                    {e.label}

                  </button>

                ))}

              </div>


              {/* ANALYZE BUTTON */}

              <button

                className="scanbtn"

                disabled={
                  !input.trim() ||
                  loading
                }

                onClick={run}

              >

                <ScanSearch size={19} />


                {loading
                  ? 'Analyzing...'
                  : 'Analyze risk'}


                <ArrowRight size={18} />

              </button>


              {/* HIDDEN PDF INPUT */}

              <input

                ref={fileInputRef}

                type="file"

                accept=".pdf,application/pdf"

                onChange={handlePDF}

                style={{
                  display: 'none'
                }}

              />


              {/* PDF BUTTON */}

              <button

                className="scanbtn"

                disabled={loading}

                onClick={() =>
                  fileInputRef.current?.click()
                }

              >

                <Upload size={19} />


                {loading
                  ? 'Processing...'
                  : 'Analyze PDF'}


                <FileText size={18} />

              </button>


              {/* PRIVACY MESSAGE */}

              <p className="micro">


                <LockKeyhole size={13} />


                Messages and documents are
                analyzed by the ScamShield backend.

              </p>


              {/* ERROR */}

              {error && (

                <div className="verify">

                  <AlertTriangle
                    size={16}
                  />

                  <span>
                    {error}
                  </span>

                </div>

              )}

            </div>


            {/* ===========================================
                RESULT PANEL
            =========================================== */}

            <div className="panel resultpanel">


              <div className="panelhead">


                <div>

                  <small>
                    02 / RESULT
                  </small>

                  <h2>
                    Your safety check
                  </h2>

                </div>


                {result && (

                  <button

                    className="iconbtn"

                    onClick={copy}

                    aria-label="Copy result"

                  >

                    {copied ? (

                      <CheckCircle2
                        size={17}
                      />

                    ) : (

                      <Copy
                        size={17}
                      />

                    )}

                  </button>

                )}

              </div>


              {/* =================================================
                  RESULT CONTENT
              ================================================= */}

              {loading ? (

                <div className="loadingstate">

                  <div className="loadingicon">

                    <ScanSearch size={34} />

                  </div>


                  <h3>
                    Analyzing...
                  </h3>


                  <p>

                    ScamShield is checking the content
                    for suspicious patterns, risky language,
                    and unsafe links.

                  </p>


                  <div className="loadingbar">

                    <span></span>

                  </div>


                  <small>

                    ML model + safety checks running

                  </small>

                </div>

              ) : !result ? (

                <div className="empty">


                  <div className="emptyicon">

                    <ShieldCheck
                      size={38}
                    />

                  </div>


                  <h3>
                    Nothing scanned yet
                  </h3>


                  <p>

                    Your ML-powered result
                    will appear here with
                    a risk level, score,
                    reasons, and what to do next.

                  </p>

                </div>

              ) : (

                <Result
                  result={result}
                />

              )}

            </div>

          </section>


          {/* =================================================
              TRUST SECTION
          ================================================= */}

          <section className="trust">


            <div>

              <CheckCircle2 />


              <strong>
                Designed for awareness
              </strong>


              <span>

                ScamShield provides an automated
                risk assessment and is not a replacement
                for your bank, email provider,
                or security software.

              </span>

            </div>


            <a href="#how">

              How it works


              <ArrowRight
                size={15}
              />

            </a>

          </section>


          {/* =================================================
              HOW IT WORKS
          ================================================= */}

          <section
            id="how"
            className="how"
          >


            <div>

              <small>
                HOW IT WORKS
              </small>


              <h2>
                ML + three safety checks.
              </h2>

            </div>


            <div className="steps">


              {/* STEP 1 */}

              <article>

                <span>
                  01
                </span>


                <ScanSearch />


                <h3>
                  Analyze signals
                </h3>


                <p>

                  The trained NLP model
                  analyzes the text while
                  ScamShield checks for
                  common scam indicators.

                </p>

              </article>


              {/* STEP 2 */}

              <article>

                <span>
                  02
                </span>


                <AlertTriangle />


                <h3>
                  Score risk
                </h3>


                <p>

                  Machine-learning predictions,
                  red flags, and document patterns
                  are combined into a risk score.

                </p>

              </article>


              {/* STEP 3 */}

              <article>

                <span>
                  03
                </span>


                <ShieldCheck />


                <h3>
                  Act safely
                </h3>


                <p>

                  Get clear next steps instead
                  of guessing whether you should
                  click, reply, upload, or pay.

                </p>

              </article>

            </div>

          </section>

        </main>

      ) : (

        <HistoryView

          history={history}

          onBack={() =>
            setTab('analyze')
          }

        />

      )}


      {/* =================================================
          FOOTER
      ================================================= */}

      <footer>


        <span>
          © 2026 ScamShield
        </span>


        <span>

          Built as a portfolio project ·
          ML-powered scam detection

        </span>

      </footer>

    </div>

  );

}


/* =========================================================
   RESULT COMPONENT
========================================================= */

function Result({ result }) {

  return (

    <div className="result">


      {/* =================================================
          RISK HEADER
      ================================================= */}

      <div className="riskrow">


        <div

          className={`riskbadge ${result.level.toLowerCase()}`}

        >

          <span className="dot"></span>


          {result.level}

        </div>


        <div className="score">

          <strong>
            {result.score}%
          </strong>

          <span>
            risk score
          </span>

        </div>

      </div>


      {/* =================================================
          RISK METER
      ================================================= */}

      <div className="meter">

        <span

          style={{
            width: `${result.score}%`
          }}

        ></span>

      </div>


      {/* =================================================
          WHY FLAGGED
      ================================================= */}

      <div className="resultsection">


        <div className="sectiontitle">

          <AlertTriangle
            size={17}
          />

          Why this was flagged

        </div>


        <ul>

          {result.reasons.map(
            (x, i) => (

              <li
                key={`${x}-${i}`}
              >

                {x}

              </li>

            )
          )}

        </ul>

      </div>


      {/* =================================================
          URL ANALYSIS
      ================================================= */}

      {result.urlFlags?.length > 0 && (

        <div className="resultsection urlanalysis">


          <div className="sectiontitle">

            <Link2
              size={17}
            />

            URL security checks

          </div>


          <ul>

            {result.urlFlags.map(
              (x, i) => (

                <li
                  key={`url-${x}-${i}`}
                >

                  {x}

                </li>

              )
            )}

          </ul>

        </div>

      )}


      {/* =================================================
          RECOMMENDED ACTION
      ================================================= */}

      <div className="advice">


        <ShieldCheck
          size={20}
        />


        <div>

          <strong>
            Recommended action
          </strong>


          <p>
            {result.safe}
          </p>

        </div>

      </div>


      {/* =================================================
          SAFETY INFORMATION
      ================================================= */}

      <div className="verify">


        <Info
          size={16}
        />


        <span>

          Never use a link or phone number
          from a suspicious message to verify
          an account. Open the official app
          or website yourself.

        </span>


        <ExternalLink
          size={14}
        />

      </div>

    </div>

  );

}


/* =========================================================
   HISTORY COMPONENT
========================================================= */

function HistoryView({
  history,
  onBack
}) {

  return (

    <main className="historypage">


      {/* =================================================
          HISTORY HERO
      ================================================= */}

      <div className="hero compact">


        <div className="pill">

          <History
            size={14}
          />

          Scan history

        </div>


        <h1>
          Your recent checks.
        </h1>


        <p>

          Results are stored only
          in this browser for this demo.

        </p>

      </div>


      {/* =================================================
          HISTORY LIST
      ================================================= */}

      {history.length ? (

        <div className="historylist">


          {history.map(
            (x, i) => (

              <button

                key={x.id || i}

                onClick={onBack}

              >


                <div

                  className={`mini ${x.level.toLowerCase()}`}

                >

                  {x.level[0]}

                </div>


                <div className="htext">


                  <strong>

                    {x.level} · {x.score}%

                  </strong>


                  <span>

                    {x.text}

                  </span>

                </div>


                <time>

                  {x.date
                    ? `${x.date} · ${x.time}`
                    : x.time}

                </time>


                <ArrowRight
                  size={17}
                />

              </button>

            )
          )}

        </div>

      ) : (


        /* =================================================
           EMPTY HISTORY
        ================================================= */

        <div className="empty historyempty">


          <History
            size={35}
          />


          <h3>
            No scans yet
          </h3>


          <p>

            Run your first safety check
            from the Analyzer.

          </p>


          <button

            className="scanbtn small"

            onClick={onBack}

          >

            Open analyzer

          </button>

        </div>

      )}

    </main>

  );

}


/* =========================================================
   START REACT APPLICATION
========================================================= */

createRoot(
  document.getElementById('root')
).render(
  <App />
);
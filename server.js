<!doctype html>
<html lang="en-CA">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover" />
  <title>Tobermory Grocery Run (TGR)</title>

  <style>
    :root{
      --black:#0b0b0b;
      --grey-0:#0f0f10;
      --grey-1:#151517;
      --grey-2:#1f2023;
      --grey-3:#2b2c31;
      --grey-4:#3a3b42;
      --light:#d9d9d9;
      --white:#ffffff;
      --red:#e3342f;
      --red-2:#ff4a44;

      --text:#ffffff;
      --muted:rgba(255,255,255,.78);
      --line:rgba(255,255,255,.18);
      --shadow:0 14px 46px rgba(0,0,0,.45);

      --radius:18px;
      --focus:0 0 0 4px rgba(227,52,47,.35);

      --fs-0:18px;
      --fs-1:20px;
      --fs-2:24px;
      --fs-3:30px;

      --pad:14px;
      --pad-lg:18px;
      --btn-h:54px;
    }

    *{ box-sizing:border-box; }
    html,body{ height:100%; }

    body{
      margin:0;
      font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;
      background:
        radial-gradient(900px 500px at 20% 0%, rgba(227,52,47,.20), transparent 55%),
        radial-gradient(900px 500px at 80% 0%, rgba(255,255,255,.10), transparent 55%),
        linear-gradient(180deg, var(--grey-0), var(--black));
      color:var(--text);
      font-size:var(--fs-0);
      line-height:1.5;
    }

    a{ color:var(--white); text-decoration:none; }
    a:hover{ text-decoration:underline; }

    .wrap{ max-width:1120px; margin:0 auto; padding:0 var(--pad); }

    #netBanner{
      display:none;
      padding:10px 12px;
      border-bottom:1px solid rgba(255,255,255,.12);
      background:rgba(227,52,47,.18);
      color:#fff;
      font-weight:1000;
    }

    header{
      position:sticky;
      top:0;
      z-index:50;
      background:rgba(11,11,11,.70);
      backdrop-filter:blur(12px);
      border-bottom:1px solid var(--line);
    }

    .hdr{
      display:flex;
      gap:14px;
      align-items:center;
      padding:14px 0;
    }

    .logo{
      width:92px;
      height:92px;
      border-radius:18px;
      border:1px solid var(--line);
      background:rgba(255,255,255,.06);
      padding:6px;
      flex:0 0 auto;
      object-fit:contain;
    }

    .hdr-title{ min-width:0; flex:1 1 auto; }
    .brand{ display:flex; align-items:baseline; gap:10px; flex-wrap:wrap; }

    .brand h1{
      margin:0;
      font-size:var(--fs-3);
      letter-spacing:.2px;
      line-height:1.1;
    }

    .tag{
      display:inline-flex;
      align-items:center;
      gap:8px;
      padding:6px 12px;
      border:1px solid var(--line);
      border-radius:999px;
      color:var(--muted);
      background:rgba(255,255,255,.06);
      font-weight:700;
      font-size:14px;
      white-space:nowrap;
    }

    .tag .dot{
      width:10px; height:10px;
      border-radius:999px;
      background:var(--red);
      box-shadow:0 0 0 4px rgba(227,52,47,.18);
    }

    .hdr-actions{
      display:flex;
      gap:10px;
      align-items:center;
      flex:0 0 auto;
      flex-wrap:wrap;
      justify-content:flex-end;
    }

    .btn{
      height:var(--btn-h);
      padding:0 16px;
      border-radius:999px;
      border:1px solid rgba(255,255,255,.20);
      background:rgba(255,255,255,.06);
      color:var(--text);
      font-weight:900;
      font-size:18px;
      display:inline-flex;
      align-items:center;
      justify-content:center;
      gap:10px;
      cursor:pointer;
      user-select:none;
      transition:transform .08s ease, background .15s ease, border-color .15s ease;
      text-decoration:none;
      white-space:nowrap;
    }

    .btn:active{ transform:translateY(1px); }
    .btn:focus{ outline:none; box-shadow:var(--focus); }

    .btn.primary{
      background:linear-gradient(180deg, var(--red-2), var(--red));
      border-color:rgba(0,0,0,.25);
      color:#fff;
      box-shadow:0 10px 30px rgba(227,52,47,.26);
    }

    .btn.secondary{
      background:rgba(217,217,217,.10);
      border-color:rgba(217,217,217,.22);
      color:var(--white);
    }

    .btn.ghost{ background:transparent; border-color:rgba(255,255,255,.20); }
    .btn.small{ height:46px; font-size:16px; padding:0 14px; }

    .tabs{
      display:flex;
      gap:10px;
      flex-wrap:wrap; 
      padding:0 0 14px;
    }

    .tab{
      height:46px;
      padding:0 14px;
      border-radius:999px;
      border:1px solid var(--line);
      background:rgba(255,255,255,.06);
      color:var(--white);
      font-weight:900;
      font-size:16px;
      cursor:pointer;
      display:inline-flex;
      align-items:center;
      gap:10px;
      white-space:nowrap;
      flex:0 0 auto;
    }

    .tab:focus{ outline:none; box-shadow:var(--focus); }

    .tab[aria-selected="true"]{
      background:rgba(227,52,47,.16);
      border-color:rgba(227,52,47,.55);
    }

    .tab .badge{
      font-size:12px;
      font-weight:900;
      padding:3px 9px;
      border-radius:999px;
      border:1px solid rgba(255,255,255,.22);
      background:rgba(255,255,255,.06);
      color:var(--muted);
    }

    main{ padding:18px 0 60px; }

    .grid{
      display:grid;
      grid-template-columns:1.25fr .75fr;
      gap:14px;
      align-items:start;
    }

    .split{
      display:grid;
      grid-template-columns:1fr 1fr;
      gap:14px;
      align-items:start;
    }

    @media (max-width:980px){
      .grid, .split{ grid-template-columns:1fr; }
      .hdr{ align-items:flex-start; }
      .logo{ width:84px; height:84px; border-radius:18px; }
      .brand h1{ font-size:28px; }
    }

    .card{
      background:rgba(255,255,255,.06);
      border:1px solid var(--line);
      border-radius:var(--radius);
      box-shadow:var(--shadow);
      padding:var(--pad-lg);
    }

    .card h2{ margin:0 0 10px; font-size:var(--fs-2); letter-spacing:.2px; }
    .muted{ color:var(--muted); }
    .hr{ height:1px; background:var(--line); margin:14px 0; }

    .pill{
      display:inline-flex;
      gap:8px;
      align-items:center;
      padding:8px 12px;
      border-radius:999px;
      border:1px solid var(--line);
      background:rgba(255,255,255,.06);
      font-weight:900;
      font-size:14px;
      color:var(--muted);
    }

    label{ display:block; font-weight:900; margin:12px 0 6px; }
    .req{ color:var(--red-2); font-weight:900; margin-left:6px; }

    input, select, textarea{
      width:100%;
      font-size:var(--fs-1);
      color:var(--white);
      background:rgba(0,0,0,.28);
      border:1px solid rgba(217,217,217,.30);
      border-radius:14px;
      padding:14px 14px;
      outline:none;
    }

    input::placeholder, textarea::placeholder{ color:rgba(255,255,255,.55); }
    input:focus, select:focus, textarea:focus{ box-shadow:var(--focus); border-color:rgba(227,52,47,.60); }
    input[readonly], input:disabled, select:disabled, textarea:disabled{ opacity:.78; }

    select{
      appearance:none;
      background-image:
        linear-gradient(45deg, transparent 50%, rgba(255,255,255,.75) 50%),
        linear-gradient(135deg, rgba(255,255,255,.75) 50%, transparent 50%);
      background-position:
        calc(100% - 26px) 50%,
        calc(100% - 18px) 50%;
      background-size:8px 8px, 8px 8px;
      background-repeat:no-repeat;
      padding-right:44px;
    }

    textarea{ min-height:120px; resize:vertical; }

    .row{ display:flex; gap:12px; flex-wrap:wrap; }
    .col{ flex:1 1 260px; min-width:240px; }

    .notice{
      border:1px solid rgba(217,217,217,.20);
      background:rgba(0,0,0,.18);
      border-radius:16px;
      padding:12px;
    }

    .notice.warn{
      border:1px solid rgba(227,52,47,.45);
      background:rgba(227,52,47,.10);
    }

    .checkrow{
      display:flex;
      gap:10px;
      align-items:flex-start;
      padding:10px 12px;
      border:1px solid rgba(255,255,255,.14);
      background:rgba(0,0,0,.18);
      border-radius:14px;
    }

    .checkrow input[type="checkbox"],
    .checkrow input[type="radio"]{
      width:22px;
      height:22px;
      margin-top:4px;
      accent-color:var(--red);
      flex:0 0 auto;
    }

    .stack{ display:flex; flex-direction:column; gap:10px; }

    .storeCard,
    .addressCard{
      border:1px solid rgba(255,255,255,.14);
      background:rgba(0,0,0,.18);
      border-radius:16px;
      padding:12px;
    }

    .addonDetails{
      display:none;
      margin-top:10px;
      padding:10px;
      border-radius:14px;
      border:1px solid rgba(255,255,255,.12);
      background:rgba(0,0,0,.18);
    }

    .addonDetails.show{ display:block; }

    .mini{
      font-size:14px;
      color:rgba(255,255,255,.75);
    }

    .profileStrip{
      display:none;
      margin-bottom:12px;
    }

    .mgrid{
      display:grid;
      grid-template-columns:repeat(2, minmax(0,1fr));
      gap:12px;
    }

    @media (max-width:900px){ .mgrid{ grid-template-columns:1fr; } }

    .mcard{
      border:1px solid rgba(255,255,255,.14);
      border-radius:16px;
      padding:14px;
      background:rgba(0,0,0,.18);
    }

    .mname{ font-weight:1000; font-size:20px; }
    .mprice{ font-weight:1000; font-size:22px; margin-top:6px; }
    .mlist{ margin:10px 0 0; padding-left:18px; }
    .mlist li{ margin:6px 0; }

    .hidden{ display:none !important; }

    footer{
      margin-top:14px;
      padding:20px 0 36px;
      color:rgba(255,255,255,.65);
      font-size:14px;
      text-align:center;
    }

    .pca { z-index: 99999 !important; }
    .pca .pcamenu { background: #ffffff !important; border-radius: 12px !important; border: 1px solid rgba(0,0,0,0.2) !important; box-shadow: 0 14px 46px rgba(0,0,0,.45) !important; overflow: hidden !important; }
    .pca .pcaitem { color: #0b0b0b !important; font-size: 16px !important; padding: 12px 14px !important; border-bottom: 1px solid rgba(0,0,0,0.05) !important; background: #ffffff !important; cursor: pointer !important; display: block !important; visibility: visible !important; }
    .pca .pcaitem:hover, .pca .pcaitem.pcafocus { background: #f0f0f0 !important; }
    .pca .pcalogo { display: none !important; }

    .autocomplete-list { position: absolute; top: 100%; left: 0; right: 0; z-index: 99; background: var(--grey-3); border: 1px solid rgba(255,255,255,.2); border-radius: 14px; max-height: 250px; overflow-y: auto; box-shadow: 0 14px 46px rgba(0,0,0,.65); margin-top: 4px; }
    .ac-item { padding: 12px 14px; border-bottom: 1px solid rgba(255,255,255,.05); cursor: pointer; transition: background 0.1s ease; }
    .ac-item:hover { background: rgba(255,255,255,.1); }
    .ac-item:last-child { border-bottom: none; }

    /* Square Payment Element Container */
    #card-container { min-height: 90px; background: #ffffff; padding: 12px; border-radius: 12px; }
  </style>
  
  <script type="text/javascript">window.$crisp=[];window.CRISP_WEBSITE_ID="a8664389-5639-47c8-8556-2c4043696f06";(function(){d=document;s=d.createElement("script");s.src="https://client.crisp.chat/l.js";s.async=1;d.getElementsByTagName("head")[0].appendChild(s);})();</script>
</head>

<body>
<div id="netBanner">Offline — some features may not work until you’re back online.</div>

<header>
  <div class="wrap">
    <div class="hdr">
      <img src="/tgr_logo_tight_512.png" class="logo" alt="Tobermory Grocery Run logo" />

      <div class="hdr-title">
        <div class="brand">
          <h1>Tobermory Grocery Run</h1>
          <span class="tag"><span class="dot"></span> Delivery • Errands • Rides</span>
        </div>
        <div class="muted" id="hdrSub">From cart to counter — your order perfected.</div>
      </div>

      <div class="hdr-actions">
        <a id="btnSignIn" class="btn secondary" href="#">Sign In</a>
        <a id="btnMember" class="btn ghost" href="#" style="display:none;">Member Portal</a>
        <a id="btnAdmin" class="btn ghost" href="#" style="display:none;">Admin</a>
      </div>
    </div>

    <div class="tabs" role="tablist" aria-label="Primary navigation">
      <button class="tab" id="tab-home" aria-selected="true" type="button">Home</button>
      <button class="tab" id="tab-about" aria-selected="false" type="button">About Us</button>
      <button class="tab" id="tab-pricing" aria-selected="false" type="button">Pricing</button>
      <button class="tab" id="tab-areas" aria-selected="false" type="button">Service Areas</button>
      <button class="tab" id="tab-estimator" aria-selected="false" type="button">Fee Estimator</button>
      <button class="tab" id="tab-order" aria-selected="false" type="button">ORDER <span class="badge">Fast</span></button>
      <button class="tab" id="tab-ride" aria-selected="false" type="button">Book a Ride</button>
      <button class="tab" id="tab-account" aria-selected="false" type="button">Create Account</button>
      <a class="tab" href="/terms.html" style="text-decoration:none;">Terms</a>
      <button class="tab" id="tab-memberships" aria-selected="false" type="button">Memberships</button>
      <button class="tab" id="tab-faq" aria-selected="false" type="button">FAQ</button>
      <button class="tab" id="tab-contact" aria-selected="false" type="button">Contact</button>
    </div>
  </div>
</header>

<main class="wrap">
  <datalist id="townSuggestions">
    <option value="Tobermory"></option>
    <option value="Dyers Bay"></option>
    <option value="Lion's Head"></option>
    <option value="Ferndale"></option>
    <option value="Wiarton"></option>
    <option value="Sauble Beach"></option>
    <option value="Southampton"></option>
    <option value="Howdenvale"></option>
    <option value="Stokes Bay"></option>
    <option value="Dunks Bay"></option>
    <option value="Bruce Peninsula"></option>
  </datalist>

  <section id="panel-home" class="card">
    <h2>Fast, reliable local runs — built for the Bruce Peninsula.</h2>
    <div class="muted">
      Groceries, prescriptions, errands, and optional rides — with a mobile-first ordering flow, membership perks, and clear tracking.
    </div>

    <div class="hr"></div>

    <div class="grid">
      <div class="card" style="box-shadow:none;background:rgba(0,0,0,.16);">
        <h2 style="margin-bottom:8px;">What we do</h2>
        <ul class="muted" style="margin:10px 0 0; padding-left:20px;">
          <li>Scheduled delivery runs with clear cutoffs</li>
          <li>Groceries, prescriptions, liquor, parcels, printing, rides, and extra stops</li>
          <li>Saved profiles so future orders auto-fill</li>
          <li>Member portal and live tracking links</li>
        </ul>

        <div class="hr"></div>

        <div class="row">
          <a class="btn primary" href="#" id="homeOrderBtn">Place an Order</a>
          <a class="btn secondary" href="#" id="homeSignInBtn">Sign In</a>
          <a class="btn ghost" href="#" id="homeMembershipBtn">Memberships</a>
          <a class="btn ghost" href="#" id="homeEstimatorBtn">Fee Estimator</a>
          <a class="btn ghost" href="mailto:orders@tobermorygroceryrun.ca">Email Orders</a>
        </div>

        <div class="muted" style="margin-top:10px;">Tip: Create your account once — future orders auto-fill your saved address and preferences.</div>
      </div>

      <aside class="card" style="box-shadow:none;background:rgba(0,0,0,.16);">
        <h2 style="margin-bottom:8px;">Quick highlights</h2>
        <div class="row" style="gap:10px;">
          <span class="pill">High-contrast UI</span>
          <span class="pill">Mobile-first</span>
          <span class="pill">Saved profiles</span>
          <span class="pill">Order IDs</span>
        </div>

        <div class="hr"></div>

        <div class="notice warn">
          <div style="font-weight:900; font-size:20px;">Member tools</div>
          <div class="muted">View your profile, orders, payment links, and tracking links in the Member Portal.</div>
          <div style="margin-top:10px;">
            <a class="btn primary small" id="goMemberBtn" href="#" style="text-decoration:none;">Open Member Portal</a>
          </div>
        </div>
      </aside>
    </div>

    <div class="hr"></div>

    <div class="card" style="box-shadow:none;background:rgba(0,0,0,.16);">
      <h2 style="margin-bottom:8px;">Scheduled Runs</h2>
      <div class="muted">Live availability and dynamic capacity updates.</div>

      <div class="hr"></div>

      <div class="split">
        <div class="card" style="box-shadow:none;background:rgba(255,255,255,.05);">
          <div style="font-weight:1000;font-size:18px;">Local Run</div>
          <div class="muted" id="homeLocalKey" title="Tap to copy">—</div>
          <div class="hr"></div>
          <div class="muted" id="homeLocalWindow">—</div>
          <div style="margin-top:10px;" class="row">
            <span class="pill" id="homeLocalOpen">—</span>
            <span class="pill" id="homeLocalSlots">Capacity: —/10 Points</span>
          </div>
          <div class="hr"></div>
          <div class="muted" id="homeLocalMin">—</div>
          <div class="row" style="margin-top:10px;">
            <span class="pill" id="homeLocalCount">Orders: —</span>
            <span class="pill" id="homeLocalFees">Fees: $—</span>
          </div>
        </div>

        <div class="card" style="box-shadow:none;background:rgba(255,255,255,.05);">
          <div style="font-weight:1000;font-size:18px;">Owen Sound Run</div>
          <div class="muted" id="homeOwenKey" title="Tap to copy">—</div>
          <div class="hr"></div>
          <div class="muted" id="homeOwenWindow">—</div>
          <div style="margin-top:10px;" class="row">
            <span class="pill" id="homeOwenOpen">—</span>
            <span class="pill" id="homeOwenSlots">Capacity: —/10 Points</span>
          </div>
          <div class="hr"></div>
          <div class="muted" id="homeOwenMin">—</div>
          <div class="row" style="margin-top:10px;">
            <span class="pill" id="homeOwenCount">Orders: —</span>
            <span class="pill" id="homeOwenFees">Fees: $—</span>
          </div>
        </div>
      </div>

      <div class="muted" id="homeRunsHint" style="margin-top:12px;"></div>
    </div>
  </section>

  <section id="panel-ride" class="card hidden">
    <h2>Book a Passenger Ride</h2>
    <div class="muted">Book a one-way seat to town. Rides take up 3 cargo space points, so availability is dynamically limited based on current grocery volume!</div>

    <div class="hr"></div>

    <form id="rideForm">
      <div class="split">
        <div class="card" style="box-shadow:none;background:rgba(0,0,0,.16);">
          <div class="stack">
            <label>Run Type<span class="req">*</span></label>
            <select id="ride_runType" required>
              <option value="local">Local Run ($15 Flat)</option>
              <option value="owen">Owen Sound Run ($50 Flat)</option>
            </select>

            <label>Pickup Location<span class="req">*</span></label>
            <input id="ride_pickup" required placeholder="Your address or pickup spot" />

            <label>Destination<span class="req">*</span></label>
            <input id="ride_dest" required placeholder="Where do you need to go?" />

            <label>Preferred Time Window</label>
            <input id="ride_window" placeholder="e.g., 10am - 12pm" />
            
            <label>Notes</label>
            <input id="ride_notes" placeholder="Accessibility, bags, trunk space needed, etc." />
          </div>
        </div>
        <div class="card" style="box-shadow:none;background:rgba(0,0,0,.16);">
          <div class="stack">
             <label>Passenger Name<span class="req">*</span></label>
             <input id="ride_name" required placeholder="Full Name" />
             
             <label>Phone Number<span class="req">*</span></label>
             <input id="ride_phone" required placeholder="519-555-1234" />
             
             <div class="checkrow" style="margin-top:14px;">
                <input id="ride_consent" type="checkbox" required />
                <div>
                  <div style="font-weight:1000;">I accept the Terms</div>
                  <div class="mini">Rides are subject to schedule changes based on grocery volume and routes.</div>
                </div>
             </div>
             
             <div class="row" style="margin-top:14px;">
               <button class="btn primary" type="submit" id="ride_submitBtn">Book Ride</button>
             </div>
             <div class="mini" id="ride_msg" style="margin-top:12px;"></div>
          </div>
        </div>
      </div>
    </form>
  </section>

  <section id="panel-about" class="card hidden">
    <h2>About Us</h2>
    <div class="muted">
      Tobermory Grocery Run is a local delivery and errands service built for clarity, accessibility, and reliability — serving the Bruce Peninsula with scheduled run windows, saved profiles, and live updates.
    </div>
  </section>

  <section id="panel-pricing" class="card hidden">
    <h2>Pricing</h2>
    <div class="muted">Pricing is based on service fee + zone + add-ons. Memberships provide discounts and perks.</div>
  </section>

  <section id="panel-areas" class="card hidden">
    <h2>Service Areas</h2>
    <div class="muted">
      We serve Tobermory and surrounding Bruce Peninsula communities. If you're outside the standard area, place the order and add details — we’ll confirm feasibility and pricing.
    </div>
  </section>

  <section id="panel-estimator" class="card hidden">
    <h2>Service & Delivery Fee Estimator</h2>
    <div class="muted">Estimates service + delivery fees only. Grocery totals are separate.</div>

    <div class="hr"></div>

    <div class="row">
      <div class="col">
        <label for="est_zone">Zone</label>
        <select id="est_zone">
          <option value="">Select…</option>
          <option value="A">Zone A</option>
          <option value="B">Zone B</option>
          <option value="C">Zone C</option>
          <option value="D">Zone D</option>
        </select>
      </div>

      <div class="col">
        <label for="est_runType">Run Type</label>
        <select id="est_runType">
          <option value="local">Local</option>
          <option value="owen">Owen Sound</option>
        </select>
        <div class="muted" id="est_runHint" style="font-size:14px;margin-top:6px;"></div>
      </div>

      <div class="col">
        <label for="est_memberTier">Membership tier</label>
        <select id="est_memberTier">
          <option value="">None</option>
          <option value="standard">Standard</option>
          <option value="route">Route</option>
          <option value="access">Access</option>
          <option value="accesspro">Access Pro</option>
        </select>
      </div>
    </div>

    <div class="row">
      <div class="col">
        <label for="est_applyPerk">Apply perk?</label>
        <select id="est_applyPerk">
          <option value="yes">Yes</option>
          <option value="no">No</option>
        </select>
      </div>

      <div class="col">
        <label for="est_extraStoresCount">Extra store stops (count)</label>
        <input id="est_extraStoresCount" type="number" min="0" value="0" />
      </div>

      <div class="col">
        <label for="est_grocerySubtotal">Estimated grocery subtotal</label>
        <input id="est_grocerySubtotal" type="number" min="0" step="0.01" value="0" />
      </div>
    </div>

    <div class="row">
      <div class="col">
        <label for="est_printing">Printing add-on?</label>
        <select id="est_printing">
          <option value="no">No</option>
          <option value="yes">Yes</option>
        </select>
      </div>

      <div class="col">
        <label for="est_printPages">Print pages</label>
        <input id="est_printPages" type="number" min="0" value="0" />
      </div>

      <div class="col">
        <label>&nbsp;</label>
        <button class="btn primary" id="est_calcBtn" type="button">Calculate</button>
      </div>
    </div>

    <div class="hr"></div>

    <div class="row" style="gap:10px;">
      <span class="pill" id="est_serviceFee">Service: —</span>
      <span class="pill" id="est_zoneFee">Zone: —</span>
      <span class="pill" id="est_runFee">Run: —</span>
      <span class="pill" id="est_addOns">Add-ons: —</span>
      <span class="pill" id="est_surcharges">Surcharges: —</span>
      <span class="pill" id="est_discount">Discount: —</span>
      <span class="pill" id="est_total">Total Fees: —</span>
    </div>

    <div class="muted" id="est_msg" style="margin-top:10px;"></div>

    <div class="hr"></div>

    <div class="row">
      <a class="btn secondary" href="#" id="est_goOrderBtn">Continue to ORDER</a>
    </div>
  </section>

  <section id="panel-order" class="card hidden">
    <h2>Place an Order</h2>
    <div class="muted">Saved profiles auto-fill the order form. Extra stops and add-on services are included below.</div>

    <div class="hr"></div>

    <div class="notice warn" id="orderGate" style="display:none;">
      <div style="font-weight:1000;">Action required</div>
      <div class="mini" id="orderGateMsg" style="margin-top:6px;"></div>
      <div class="row" style="margin-top:10px;">
        <button class="btn primary small" id="orderGateBtn" type="button">Continue</button>
        <button class="btn small ghost" id="orderGateGoAccount" type="button" style="display:none;">Create Account</button>
      </div>
    </div>

    <div class="profileStrip notice" id="orderProfileStrip">
      <div class="row" style="justify-content:space-between;">
        <div>
          <div style="font-weight:1000;">Saved profile loaded</div>
          <div class="mini" id="orderProfileSummary">—</div>
        </div>
        <div class="row">
          <select id="ord_savedAddress" style="min-width:260px;"></select>
          <button class="btn small" type="button" id="ord_reloadProfile">Reload</button>
          <button class="btn small ghost" type="button" id="ord_editProfile">Edit Profile</button>
        </div>
      </div>
    </div>

    <form id="orderForm" enctype="multipart/form-data">
      <div class="split">
        <div class="card" style="box-shadow:none;background:rgba(0,0,0,.16);">
          <div style="font-weight:1000;font-size:18px;">Run + Delivery Details</div>
          <div class="hr"></div>

          <div class="row">
            <div class="col">
              <label for="ord_runType">Run Type<span class="req">*</span></label>
              <select id="ord_runType" required>
                <option value="local">Local</option>
                <option value="owen">Owen Sound</option>
              </select>
              <div class="mini" id="ord_runStatus" style="margin-top:6px;"></div>
            </div>

            <div class="col">
              <label for="ord_zone">Zone<span class="req">*</span></label>
              <select id="ord_zone" required>
                <option value="">Select…</option>
                <option value="A">Zone A</option>
                <option value="B">Zone B</option>
                <option value="C">Zone C</option>
                <option value="D">Zone D</option>
              </select>
            </div>
          </div>

          <label for="ord_lookup">Road address lookup (Canada Post)</label>
          <input id="ord_lookup" class="addr_lookup" placeholder="Start typing your street address" autocomplete="off" />
          <div class="mini">Selecting a suggestion fills street, unit, town, and postal code. Zone stays manual.</div>

          <div class="row">
            <div class="col">
              <label for="ord_town">Town / City<span class="req">*</span></label>
              <input id="ord_town" list="townSuggestions" required placeholder="Town / city" />
            </div>
            <div class="col">
              <label for="ord_postal">Postal Code<span class="req">*</span></label>
              <input id="ord_postal" required placeholder="e.g., N0H 2R0" autocomplete="postal-code" />
            </div>
          </div>

          <div class="row">
            <div class="col">
              <label for="ord_street">Street Address<span class="req">*</span></label>
              <input id="ord_street" required placeholder="123 Main St" autocomplete="street-address" />
            </div>
            <div class="col">
              <label for="ord_unit">Unit / Apt / Cabin</label>
              <input id="ord_unit" placeholder="Optional" autocomplete="address-line2" />
            </div>
          </div>

          <div class="hr"></div>

          <div style="font-weight:1000;font-size:18px;">Contact for This Order</div>

          <div class="row">
            <div class="col">
              <label for="ord_name">Full Name<span class="req">*</span></label>
              <input id="ord_name" required placeholder="First + last name" autocomplete="name" />
            </div>
            <div class="col">
              <label for="ord_phone">Phone<span class="req">*</span></label>
              <input id="ord_phone" required placeholder="e.g., 519-555-1234" autocomplete="tel" />
            </div>
          </div>

          <div class="row">
            <div class="col">
              <label for="ord_email">Email</label>
              <input id="ord_email" disabled />
            </div>
            <div class="col">
              <label for="ord_dob">Date of Birth</label>
              <input id="ord_dob" type="date" />
            </div>
          </div>

          <div class="row">
            <div class="col">
              <label for="ord_contactPref">Contact preference<span class="req">*</span></label>
              <select id="ord_contactPref" required>
                <option value="">Select…</option>
                <option value="Text">Text</option>
                <option value="Phone call">Phone call</option>
                <option value="Email">Email</option>
              </select>
            </div>

            <div class="col">
              <label for="ord_memberTier">Membership level</label>
              <select id="ord_memberTier">
                <option value="">None</option>
                <option value="standard">Standard</option>
                <option value="route">Route</option>
                <option value="access">Access</option>
                <option value="accesspro">Access Pro</option>
              </select>
            </div>
          </div>
        </div>

        <div class="card" style="box-shadow:none;background:rgba(0,0,0,.16);">
          <div style="font-weight:1000;font-size:18px;">Store + Grocery List</div>
          <div class="hr"></div>

          <label for="ord_primaryStore">Primary Store<span class="req">*</span></label>
          <select id="ord_primaryStore" required></select>
          <div class="mini">Store options change automatically based on run type.</div>

          <div class="hr"></div>

          <label>Grocery / shopping list<span class="req">*</span></label>
          <div class="mini" style="margin-bottom:10px;">Search the catalogue for estimates, or type a custom item.</div>
          
          <div style="position:relative;">
            <div class="row">
              <input id="itemSearchInput" autocomplete="off" placeholder="e.g., Milk 2% 4L, Bread..." style="flex:1;" />
              <button type="button" class="btn secondary" id="btnAddItem">Add</button>
            </div>
            <div id="autocompleteDropdown" class="autocomplete-list" style="display:none;"></div>
          </div>

          <div id="groceryListItems" class="stack" style="margin-top:14px;"></div>

          <div class="row" style="justify-content:space-between; margin-top:14px; padding-top:14px; border-top:1px solid rgba(255,255,255,.1);">
             <div style="font-weight:1000;">Catalogue Estimate:</div>
             <div style="font-weight:1000; color:var(--red-2);" id="uiGroceryTotal">$0.00</div>
          </div>

          <textarea id="ord_groceryList" style="display:none;"></textarea>

          <div class="row" style="margin-top:10px;">
            <div class="col">
              <label for="ord_groceryFile">Upload a list (optional)</label>
              <input id="ord_groceryFile" type="file" accept=".jpg,.jpeg,.png,.pdf,.txt" />
            </div>

            <div class="col">
              <label for="ord_grocerySubtotal">Estimated grocery subtotal</label>
              <input id="ord_grocerySubtotal" type="number" min="0" step="0.01" value="0" />
              <div class="mini">Automatically tallies from catalogue items. Adjust if needed.</div>
            </div>
          </div>

          <div class="hr"></div>

          <div style="font-weight:1000;font-size:18px;">Preferences</div>

          <div class="row">
            <div class="col">
              <label for="ord_dropoffPref">Drop-off preference<span class="req">*</span></label>
              <select id="ord_dropoffPref" required>
                <option value="">Select…</option>
                <option value="Leave at door">Leave at door</option>
                <option value="Knock / ring bell">Knock / ring bell</option>
                <option value="Call on arrival">Call on arrival</option>
                <option value="Hand to me">Hand to me</option>
              </select>
            </div>

            <div class="col">
              <label for="ord_subsPref">Substitutions<span class="req">*</span></label>
              <select id="ord_subsPref" required>
                <option value="">Select…</option>
                <option value="Allow substitutions">Allow substitutions</option>
                <option value="No substitutions">No substitutions</option>
                <option value="Text/call me for substitutions">Text/call me for substitutions</option>
              </select>
            </div>
          </div>

          <div class="row">
            <div class="col">
              <label for="ord_gateCode">Gate / buzzer code</label>
              <input id="ord_gateCode" placeholder="Optional" />
            </div>

            <div class="col">
              <label for="ord_budgetCap">Budget cap</label>
              <input id="ord_budgetCap" type="number" min="0" step="0.01" value="0" placeholder="0 = no cap" />
            </div>
          </div>

          <label for="ord_accessNotes">Building access notes</label>
          <input id="ord_accessNotes" placeholder="Entrance, stairs, side door, etc." />

          <label for="ord_parkingNotes">Parking / approach notes</label>
          <input id="ord_parkingNotes" placeholder="Driveway, parking, gate, snow, etc." />

          <div class="row">
            <div class="col">
              <label for="ord_receiptPref">Receipt preference</label>
              <select id="ord_receiptPref">
                <option value="">No preference</option>
                <option value="Leave receipt in bags">Leave receipt in bags</option>
                <option value="Photo of receipt (text)">Photo of receipt (text)</option>
                <option value="Photo of receipt (email)">Photo of receipt (email)</option>
              </select>
            </div>

            <div class="col">
              <label>&nbsp;</label>
              <div class="checkrow">
                <input id="ord_photoProofOk" type="checkbox" />
                <div>
                  <div style="font-weight:1000;">Photo proof OK</div>
                  <div class="mini">Optional photo of bags at the drop point.</div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div class="hr"></div>

      <div class="split">
        <div class="stack">
          <div class="card" style="box-shadow:none;background:rgba(0,0,0,.16);">
            <div style="font-weight:1000;font-size:18px;">Extra Store Stops</div>
            <div class="mini">Add as many extra stops as you need.</div>
            <div class="hr"></div>

            <div id="extraStoresWrap" class="stack"></div>

            <div class="row" style="margin-top:10px;">
              <button class="btn small" type="button" id="btnAddStore">+ Add store stop</button>
              <button class="btn small ghost" type="button" id="btnClearStores">Clear</button>
            </div>

            <div class="mini" style="margin-top:10px;">Examples: LCBO, pharmacy, Home Hardware, post office, parcel depot.</div>
          </div>

          <div class="card" style="box-shadow:none;background:rgba(0,0,0,.16);">
            <div style="font-weight:1000;font-size:18px;">Consents & Payment<span class="req">*</span></div>
            <div class="mini">Required to submit the order.</div>
            <div class="hr"></div>

            <div class="stack">
              <div class="checkrow">
                <input id="consent_terms" type="checkbox" />
                <div><div style="font-weight:1000;">I agree to the Terms</div></div>
              </div>
              <div class="checkrow">
                <input id="consent_accuracy" type="checkbox" />
                <div><div style="font-weight:1000;">My information is accurate</div></div>
              </div>
              <div class="checkrow">
                <input id="consent_dropoff" type="checkbox" />
                <div><div style="font-weight:1000;">Drop-off authorization</div></div>
              </div>
            </div>

            <div class="hr"></div>

            <div class="card" style="box-shadow:none; background:rgba(255,255,255,.05); border-color: rgba(227,52,47,.5);">
              <div style="font-weight:1000; font-size:16px;">Payment Authorization</div>
              <div class="mini" style="margin-bottom:10px;">We will place a hold on your card for the estimated total + 15% buffer. You will only be charged the exact receipt total + fees upon delivery.</div>
              <div id="card-container"></div>
            </div>

            <div class="row" style="justify-content:space-between; align-items:center; margin-top:14px;">
              <div>
                <div class="pill" id="ord_feePreview">Estimated fees: —</div>
              </div>
              <div class="row">
                <button class="btn ghost" type="button" id="ord_calcFeesBtn">Estimate Fees</button>
                <button class="btn primary" type="submit" id="ord_submitBtn">Authorize & Submit</button>
              </div>
            </div>

            <div class="mini" id="ord_msg" style="margin-top:12px;"></div>
          </div>
        </div>

        <div class="card" style="box-shadow:none;background:rgba(0,0,0,.16);">
          <div style="font-weight:1000;font-size:18px;">Add-ons & Special Requests</div>
          <div class="mini">Check an add-on to reveal its detail fields.</div>
          <div class="hr"></div>

          <div class="stack">
            <div class="checkrow">
              <input id="addon_prescription" type="checkbox" />
              <div style="flex:1;"><div style="font-weight:1000;">Prescription pickup & delivery</div>
                <div class="addonDetails" id="prescDetails"><div class="row"><div class="col"><input id="presc_pharmacy" placeholder="Pharmacy name" /></div><div class="col"><input id="presc_notes" placeholder="Notes" /></div></div></div>
              </div>
            </div>
            <div class="checkrow">
              <input id="addon_liquor" type="checkbox" />
              <div style="flex:1;"><div style="font-weight:1000;">Liquor pickup & delivery</div>
                <div class="addonDetails" id="liqDetails"><div class="row"><div class="col"><input id="liq_store" placeholder="Store name" /></div><div class="col"><input id="liq_notes" placeholder="Notes" /></div></div></div>
              </div>
            </div>
            <div class="checkrow">
              <input id="addon_printing" type="checkbox" />
              <div style="flex:1;"><div style="font-weight:1000;">Printing / scanning / faxing</div>
                <div class="addonDetails" id="printDetails"><div class="row"><div class="col"><input id="addon_printPages" type="number" min="0" value="0" /></div><div class="col"><input id="addon_printNotes" placeholder="Notes" /></div></div></div>
              </div>
            </div>
            <div class="checkrow">
              <input id="addon_fastfood" type="checkbox" />
              <div style="flex:1;"><div style="font-weight:1000;">Fast food pickup</div>
                <div class="addonDetails" id="ffDetails"><div class="row"><div class="col"><input id="ff_rest" placeholder="Restaurant name" /></div><div class="col"><input id="ff_order" placeholder="Order details" /></div></div></div>
              </div>
            </div>
            <div class="checkrow">
              <input id="addon_parcel" type="checkbox" />
              <div style="flex:1;"><div style="font-weight:1000;">Parcel drop-off / pickup</div>
                <div class="addonDetails" id="parcelDetails"><div class="row"><div class="col"><input id="par_carrier" placeholder="Carrier" /></div><div class="col"><input id="par_details" placeholder="Details" /></div></div></div>
              </div>
            </div>
            <div class="checkrow">
              <input id="addon_bulky" type="checkbox" />
              <div style="flex:1;"><div style="font-weight:1000;">Bulky / heavy items</div>
                <div class="addonDetails" id="bulkyDetails"><input id="bulky_notes" placeholder="Cases of water, large items, pet food, etc." /></div>
              </div>
            </div>
            <div>
              <label for="ord_optionalNotes">Additional notes</label>
              <textarea id="ord_optionalNotes" placeholder="Delivery notes, preferred brands, accessibility notes, other errands, etc."></textarea>
            </div>
          </div>
        </div>
      </div>
    </form>
  </section>

  <section id="panel-account" class="card hidden">
    <h2>Create Account / Edit Profile</h2>
    <div class="muted">Complete this once. Your saved contact details, address, and defaults will auto-fill future orders.</div>
    <div class="hr"></div>
    <div class="notice warn" id="acctGate" style="display:none;">
      <div style="font-weight:1000;">Action required</div>
      <div class="mini" id="acctGateMsg" style="margin-top:6px;"></div>
      <div class="row" style="margin-top:10px;"><button class="btn primary small" id="acctGateBtn" type="button">Continue</button></div>
    </div>

    <form id="acctForm">
      <div class="split">
        <div class="card" style="box-shadow:none;background:rgba(0,0,0,.16);">
          <div style="font-weight:1000;font-size:18px;">Contact</div><div class="hr"></div>
          <div class="row"><div class="col"><label for="acc_fullName">Full legal name<span class="req">*</span></label><input id="acc_fullName" required /></div><div class="col"><label for="acc_preferredName">Preferred name</label><input id="acc_preferredName" /></div></div>
          <div class="row"><div class="col"><label for="acc_phone">Phone<span class="req">*</span></label><input id="acc_phone" required /></div><div class="col"><label for="acc_altPhone">Alternate phone</label><input id="acc_altPhone" /></div></div>
          <div class="row">
            <div class="col"><label for="acc_contactPref">Contact preference<span class="req">*</span></label><select id="acc_contactPref" required><option value="">Select…</option><option value="Text">Text</option><option value="Phone call">Phone call</option><option value="Email">Email</option></select></div>
            <div class="col"><label>&nbsp;</label><div class="checkrow"><input id="acc_contactAuth" type="checkbox" /><div><div style="font-weight:1000;">Authorize contact<span class="req">*</span></div><div class="mini">Required for substitutions and delivery coordination.</div></div></div></div>
          </div>
          <div class="hr"></div>
          <div style="font-weight:1000;font-size:18px;">Saved Defaults</div>
          <div class="row"><div class="col"><label for="acc_subsDefault">Default substitutions</label><select id="acc_subsDefault"><option value="">(none)</option><option value="Allow substitutions">Allow substitutions</option><option value="No substitutions">No substitutions</option><option value="Text/call me for substitutions">Text/call me for substitutions</option></select></div><div class="col"><label for="acc_dropoffDefault">Default drop-off</label><select id="acc_dropoffDefault"><option value="">(none)</option><option value="Leave at door">Leave at door</option><option value="Knock / ring bell">Knock / ring bell</option><option value="Call on arrival">Call on arrival</option><option value="Hand to me">Hand to me</option></select></div></div>
          <label for="acc_notes">Notes</label><textarea id="acc_notes" placeholder="Accessibility, regular preferences, account notes, etc."></textarea>
        </div>

        <div class="card" style="box-shadow:none;background:rgba(0,0,0,.16);">
          <div style="font-weight:1000;font-size:18px;">Saved Addresses</div><div class="mini">You can save more than one address and choose a default.</div><div class="hr"></div>
          <div id="acc_addresses" class="stack"></div>
          <div class="row" style="margin-top:10px;"><button class="btn small" type="button" id="acc_addAddress">+ Add saved address</button><button class="btn small ghost" type="button" id="acc_loadBtn">Load Existing</button></div>
          <div class="hr"></div>
          <div style="font-weight:1000;font-size:18px;">Consents<span class="req">*</span></div>
          <div class="stack">
            <div class="checkrow"><input id="acc_consentTerms" type="checkbox" /><div><div style="font-weight:1000;">Accept Terms</div><div class="mini">Required.</div></div></div>
            <div class="checkrow"><input id="acc_consentPrivacy" type="checkbox" /><div><div style="font-weight:1000;">Accept Privacy / data handling</div><div class="mini">Required.</div></div></div>
            <div class="checkrow"><input id="acc_consentMarketing" type="checkbox" /><div><div style="font-weight:1000;">Marketing consent</div><div class="mini">Optional.</div></div></div>
          </div>
          <div class="hr"></div>
          <div class="row"><button class="btn primary" type="submit" id="acc_saveBtn">Save Profile</button></div>
          <div class="mini" id="acc_msg" style="margin-top:10px;"></div>
        </div>
      </div>
    </form>
  </section>

  <section id="panel-memberships" class="card hidden">
    <h2>Memberships</h2><div class="muted">Monthly memberships. Buy through Square using the buttons below.</div><div class="hr"></div>
    <div class="mgrid">
      <div class="mcard"><div class="mname">Standard</div><div class="mprice">$15 / month</div><ul class="mlist muted"><li>1 free add-on up to $10 OR $10 off zone fee monthly</li></ul><div class="row" style="margin-top:12px;"><a class="btn primary small" id="buyStandard" href="#" target="_blank" rel="noopener">Buy Standard</a></div></div>
      <div class="mcard"><div class="mname">Route</div><div class="mprice">$25 / month</div><ul class="mlist muted"><li>1 free add-on up to $10 OR $10 off zone fee monthly</li><li>$5 off service fee on 1 order per run day</li></ul><div class="row" style="margin-top:12px;"><a class="btn primary small" id="buyRoute" href="#" target="_blank" rel="noopener">Buy Route</a></div></div>
      <div class="mcard"><div class="mname">Access</div><div class="mprice">$12 / month</div><ul class="mlist muted"><li>Seniors 60+ / disabled</li><li>1 free add-on up to $10 OR $10 off zone fee per run cycle</li><li>$8 off service fee on 1 order per run day</li><li>Free phone/text ordering</li></ul><div class="row" style="margin-top:12px;"><a class="btn primary small" id="buyAccess" href="#" target="_blank" rel="noopener">Buy Access</a></div></div>
      <div class="mcard"><div class="mname">Access Pro</div><div class="mprice">$20 / month</div><ul class="mlist muted"><li>$10 off service fee on 1 order per run day</li><li>1 prescription pickup/delivery included monthly</li><li>Document services included up to 10 pages/month in Tobermory area</li></ul><div class="row" style="margin-top:12px;"><a class="btn primary small" id="buyAccessPro" href="#" target="_blank" rel="noopener">Buy Access Pro</a></div></div>
    </div>
  </section>

  <section id="panel-faq" class="card hidden"><h2>FAQ</h2><div class="muted">Common questions.</div></section>
  <section id="panel-contact" class="card hidden"><h2>Contact</h2><div class="muted">Fastest ways to reach us.</div><div class="hr"></div><ul class="muted" style="margin:0; padding-left:20px;"><li>Email orders: <a href="mailto:orders@tobermorygroceryrun.ca">orders@tobermorygroceryrun.ca</a></li><li>General: <a href="mailto:info@tobermorygroceryrun.ca">info@tobermorygroceryrun.ca</a></li></ul></section>

  <footer>© <span id="year"></span> Tobermory Grocery Run • Candy red / light grey / black</footer>
</main>

<script>
  const BACKEND = "https://api.tobermorygroceryrun.ca";
  const API_ME = BACKEND + "/api/me";
  const API_RUNS = BACKEND + "/api/runs/active";
  const API_ESTIMATOR = BACKEND + "/api/estimator";
  const API_CONFIG = BACKEND + "/api/public/config";
  const API_PROFILE = BACKEND + "/api/profile";
  const API_ORDERS = BACKEND + "/api/orders";

  const STORES_BY_RUN = { local: ["Foodland (Tobermory)", "Foodland (Lion's Head)", "Foodland (Wiarton)"], owen: ["Walmart (Owen Sound)", "FreshCo (Owen Sound)", "Giant Tiger (Owen Sound)", "Zehrs (Owen Sound)", "Metro (Owen Sound)", "Foodland (Owen Sound)", "No Frills (Owen Sound)", "Food Basics (Owen Sound)"] };

  let meCache = { loggedIn:false, profileComplete:false, email:"", name:"", membershipLevel:"none", membershipStatus:"inactive", isAdmin:false };
  let cachedRuns = null; let profileCache = null; let membershipLinks = {}; let canadaPostKey = ""; let acCounter = 0;
  let currentGroceryList = [];

  // SQUARE INTEGRATION VARIABLES
  let squarePayments = null;
  let squareCard = null;

  const tabs = [
    { tab: "tab-home", panel: "panel-home" }, { tab: "tab-about", panel: "panel-about" }, { tab: "tab-pricing", panel: "panel-pricing" }, { tab: "tab-areas", panel: "panel-areas" }, { tab: "tab-estimator", panel: "panel-estimator" }, { tab: "tab-order", panel: "panel-order" }, { tab: "tab-ride", panel: "panel-ride" }, { tab: "tab-account", panel: "panel-account" }, { tab: "tab-memberships", panel: "panel-memberships" }, { tab: "tab-faq", panel: "panel-faq" }, { tab: "tab-contact", panel: "panel-contact" }
  ];

  const qs = (id) => document.getElementById(id); const qsa = (sel, root=document) => Array.from(root.querySelectorAll(sel));

  function selectTab(tabId){
    tabs.forEach(t => {
      const tabEl = qs(t.tab); const panelEl = qs(t.panel); if (!tabEl || !panelEl) return;
      const active = (t.tab === tabId); tabEl.setAttribute("aria-selected", active ? "true" : "false"); panelEl.classList.toggle("hidden", !active);
    });
    window.scrollTo({ top: 0, behavior: "smooth" });
  }
  tabs.forEach(t => { const el = qs(t.tab); if (!el) return; el.addEventListener("click", () => selectTab(t.tab)); });

  function initOfflineBanner(){ const banner = qs("netBanner"); const sync = () => { banner.style.display = navigator.onLine ? "none" : "block"; }; window.addEventListener("online", sync); window.addEventListener("offline", sync); sync(); }
  async function copyText(text){ try { await navigator.clipboard.writeText(String(text || "")); return true; } catch { return false; } }

  async function getMe(){ try{ const r = await fetch(API_ME, { credentials:"include" }); const d = await r.json().catch(()=>({})); if (r.ok && d.ok) meCache = d; return d; } catch { return {}; } }

  function loadCanadaPostScript(key) {
    if (document.getElementById("pca-script")) return;
    const css = document.createElement("link"); css.rel = "stylesheet"; css.href = `https://ws1.postescanada-canadapost.ca/css/addresscomplete-2.50.min.css?key=${encodeURIComponent(key)}`; document.head.appendChild(css);
    const script = document.createElement("script"); script.id = "pca-script"; script.src = `https://ws1.postescanada-canadapost.ca/js/addresscomplete-2.50.min.js?key=${encodeURIComponent(key)}`; document.head.appendChild(script);
  }

  // INITIALIZE SQUARE SDK
  async function initSquare(appId, locationId, env) {
    if (!appId || !locationId) return;
    const script = document.createElement("script");
    script.src = env === "production" ? "https://web.squarecdn.com/v1/square.js" : "https://sandbox.web.squarecdn.com/v1/square.js";
    script.onload = async () => {
      try {
        squarePayments = window.Square.payments(appId, locationId);
        squareCard = await squarePayments.card();
        await squareCard.attach('#card-container');
      } catch (e) {
        console.error("Square initialization failed:", e);
      }
    };
    document.head.appendChild(script);
  }

  async function loadConfig(){
    try{
      const r = await fetch(API_CONFIG); const d = await r.json().catch(()=>({}));
      if (r.ok && d.ok){
        membershipLinks = d.squareMembershipLinks || {};
        canadaPostKey = d.canadaPostKey || "";
        if (canadaPostKey) loadCanadaPostScript(canadaPostKey);
        
        // Load Square Web Payments SDK
        initSquare(d.squareAppId, d.squareLocationId, d.squareEnv);
      }
    } catch {}
  }

  function goLogin(returnToUrl){
    const w = 500; const h = 600; const y = window.top.outerHeight / 2 + window.top.screenY - ( h / 2); const x = window.top.outerWidth / 2 + window.top.screenX - ( w / 2);
    const popup = window.open(BACKEND + "/auth/google?returnTo=popup", "GoogleLogin", `width=${w},height=${h},top=${y},left=${x}`);
    const timer = setInterval(async () => {
      if (popup && popup.closed) {
        clearInterval(timer); await initAuthUI();
        if (meCache.loggedIn) { await loadProfile(); if (profileCache) populateAccountForm(profileCache); if (meCache.profileComplete) selectTab("tab-order"); else selectTab("tab-account"); }
      }
    }, 500);
  }

  function syncAccountTabVisibility(){ const tab = qs("tab-account"); if (!tab) return; tab.style.display = ""; tab.textContent = (meCache.loggedIn && meCache.profileComplete) ? "Edit Profile" : "Create Account"; }

  function bindHeaderButtons(){
    qs("btnSignIn").addEventListener("click", (e) => { e.preventDefault(); if (meCache.loggedIn) window.location.href = BACKEND + "/logout?returnTo=" + encodeURIComponent("https://tobermorygroceryrun.ca/"); else goLogin("https://tobermorygroceryrun.ca/"); });
    qs("homeSignInBtn").addEventListener("click", (e) => { e.preventDefault(); goLogin("https://tobermorygroceryrun.ca/"); });
    qs("homeMembershipBtn").addEventListener("click", (e) => { e.preventDefault(); selectTab("tab-memberships"); });
    qs("homeEstimatorBtn").addEventListener("click", (e) => { e.preventDefault(); selectTab("tab-estimator"); });
    qs("homeOrderBtn").addEventListener("click", async (e) => { e.preventDefault(); await getMe(); if (!meCache.loggedIn) return goLogin("https://tobermorygroceryrun.ca/?tab=account"); if (!meCache.profileComplete) return selectTab("tab-account"); selectTab("tab-order"); });
    qs("goMemberBtn").addEventListener("click", (e) => { e.preventDefault(); if (!meCache.loggedIn) return goLogin("https://tobermorygroceryrun.ca/"); window.location.href = BACKEND + "/member"; });
    qs("est_goOrderBtn").addEventListener("click", (e) => { e.preventDefault(); selectTab("tab-order"); });
  }

  async function initAuthUI(){
    await getMe(); const signIn = qs("btnSignIn"); const member = qs("btnMember"); const admin = qs("btnAdmin");
    if (meCache.loggedIn){
      signIn.classList.remove("secondary"); signIn.classList.add("ghost"); signIn.textContent = "Log out";
      member.style.display = ""; member.href = BACKEND + "/member"; member.textContent = "Member Portal";
      if (meCache.isAdmin){ admin.style.display = ""; admin.href = BACKEND + "/admin"; admin.textContent = "Admin"; } else { admin.style.display = "none"; }
    } else {
      signIn.classList.add("secondary"); signIn.classList.remove("ghost"); signIn.textContent = "Sign In";
      member.style.display = "none"; admin.style.display = "none";
    }
    syncAccountTabVisibility();
  }

  function initMembershipLinks(){
    if (qs("buyStandard")) qs("buyStandard").href = membershipLinks.standard || "#"; if (qs("buyRoute")) qs("buyRoute").href = membershipLinks.route || "#"; if (qs("buyAccess")) qs("buyAccess").href = membershipLinks.access || "#"; if (qs("buyAccessPro")) qs("buyAccessPro").href = membershipLinks.accesspro || "#";
  }

  function renderRunsHome(runs){
    if (!runs) return; const local = runs.local || {}; const owen = runs.owen || {};
    qs("homeLocalKey").textContent = local.runKey || "—"; qs("homeLocalWindow").textContent = "Opens: " + (local.opensAtLocal || "—") + " • Cutoff: " + (local.cutoffAtLocal || "—"); qs("homeLocalOpen").textContent = local.isOpen ? "OPEN ✅" : "CLOSED"; qs("homeLocalSlots").textContent = "Capacity: " + (local.bookedPoints || 0) + "/" + (local.maxPoints || 10) + " Points"; qs("homeLocalMin").textContent = local.minimumText || "—"; qs("homeLocalCount").textContent = "Orders: " + (local.bookedOrdersCount ?? "—"); qs("homeLocalFees").textContent = "Fees: $" + Number(local.bookedFeesTotal || 0).toFixed(2);
    qs("homeOwenKey").textContent = owen.runKey || "—"; qs("homeOwenWindow").textContent = "Opens: " + (owen.opensAtLocal || "—") + " • Cutoff: " + (owen.cutoffAtLocal || "—"); qs("homeOwenOpen").textContent = owen.isOpen ? "OPEN ✅" : "CLOSED"; qs("homeOwenSlots").textContent = "Capacity: " + (owen.bookedPoints || 0) + "/" + (owen.maxPoints || 10) + " Points"; qs("homeOwenMin").textContent = owen.minimumText || "—"; qs("homeOwenCount").textContent = "Orders: " + (owen.bookedOrdersCount ?? "—"); qs("homeOwenFees").textContent = "Fees: $" + Number(owen.bookedFeesTotal || 0).toFixed(2);
    qs("homeRunsHint").textContent = (!!local.isOpen || !!owen.isOpen) ? "At least one run is currently open for ordering." : "No run is open for ordering.";
    if (local.runKey){ qs("homeLocalKey").style.cursor = "pointer"; qs("homeLocalKey").onclick = async () => { await copyText(local.runKey); }; }
    if (owen.runKey){ qs("homeOwenKey").style.cursor = "pointer"; qs("homeOwenKey").onclick = async () => { await copyText(owen.runKey); }; }
    updateEstimatorRunHint(); updateOrderRunStatus();
  }

  async function loadRuns(){ try{ const r = await fetch(API_RUNS, { credentials:"include" }); const d = await r.json().catch(()=>({})); if (!r.ok || d.ok === false) throw new Error(d.error || "Runs unavailable"); cachedRuns = d.runs || null; renderRunsHome(cachedRuns); } catch { qs("homeRunsHint").textContent = "Runs unavailable right now."; } }

  function dollars(n){ return "$" + Number(n || 0).toFixed(2); }

  function buildEstimatorPayload(){
    const extraStoresCount = Number(qs("est_extraStoresCount").value || 0); const extraStores = Array.from({ length: Math.max(0, extraStoresCount) }, (_, i) => "Stop " + (i + 1));
    return { zone: qs("est_zone").value, runType: qs("est_runType").value, memberTier: qs("est_memberTier").value, applyPerk: qs("est_applyPerk").value, extraStores, addon_printing: qs("est_printing").value, printPages: Number(qs("est_printPages").value || 0), grocerySubtotal: Number(qs("est_grocerySubtotal").value || 0) };
  }

  function updateEstimatorRunHint(){
    const hint = qs("est_runHint"); const rt = qs("est_runType").value; if (!hint) return; if (!cachedRuns || !cachedRuns[rt]){ hint.textContent = ""; return; } const rr = cachedRuns[rt];
    hint.textContent = "Cutoff: " + (rr.cutoffAtLocal || "—") + " • Capacity Points: " + (rr.bookedPoints || 0) + "/" + (rr.maxPoints || 10);
  }

  async function runEstimator(){
    qs("est_msg").textContent = "Calculating…";
    try{
      const r = await fetch(API_ESTIMATOR, { method:"POST", headers:{ "Content-Type":"application/json" }, body: JSON.stringify(buildEstimatorPayload()) }); const d = await r.json().catch(()=>({}));
      if (!r.ok || d.ok === false) throw new Error(d.error || "Estimator failed"); const t = d.breakdown?.totals || {};
      qs("est_serviceFee").textContent = "Service: " + dollars(t.serviceFee); qs("est_zoneFee").textContent = "Zone: " + dollars(t.zoneFee); qs("est_runFee").textContent = "Run: " + dollars(t.runFee); qs("est_addOns").textContent = "Add-ons: " + dollars(t.addOnsFees); qs("est_surcharges").textContent = "Surcharges: " + dollars(t.surcharges); qs("est_discount").textContent = "Discount: -" + dollars(t.discount); qs("est_total").textContent = "Total Fees: " + dollars(t.totalFees); qs("est_msg").textContent = "Estimate complete ✅";
    } catch (e){ qs("est_msg").textContent = String(e.message || e); }
  }

  function bindEstimatorUI(){ qs("est_calcBtn").addEventListener("click", runEstimator); qs("est_runType").addEventListener("change", updateEstimatorRunHint); }

  function nextAcId(prefix){ acCounter += 1; return prefix + "_" + acCounter; }

  const initAcDelegator = (e) => {
    if (e.target && e.target.classList.contains("addr_lookup")) {
      const lookupEl = e.target; if (lookupEl.dataset.acBound === "1") return; if (!canadaPostKey || typeof pca === "undefined" || !pca.Address) return;
      const lookupId = lookupEl.id; let streetId, unitId, townId, postalId;
      if (lookupId === "ord_lookup") { streetId = "ord_street"; unitId = "ord_unit"; townId = "ord_town"; postalId = "ord_postal"; } else { const prefix = lookupId.replace("_lookup", ""); streetId = prefix + "_street"; unitId = prefix + "_unit"; townId = prefix + "_town"; postalId = prefix + "_postal"; }
      try {
        const fields = [ { element: lookupId, field: "", mode: pca.fieldMode.SEARCH }, { element: streetId, field: "Line1", mode: pca.fieldMode.POPULATE }, { element: unitId, field: "Line2", mode: pca.fieldMode.POPULATE }, { element: townId, field: "City", mode: pca.fieldMode.POPULATE }, { element: postalId, field: "PostalCode", mode: pca.fieldMode.POPULATE } ];
        const options = { key: canadaPostKey, countries: { codesList: "CAN" } }; const control = new pca.Address(fields, options); control.listen("load", function() { control.setCountry("CAN"); }); lookupEl.dataset.acBound = "1"; lookupEl._pcaControl = control;
      } catch (err) { console.error("AddressComplete Error:", err); }
    }
  };
  document.addEventListener("focusin", initAcDelegator, true); document.addEventListener("click", initAcDelegator, true);

  let acTimeout; function hideAc() { qs("autocompleteDropdown").style.display = "none"; }
  async function doCatalogueSearch(q) { if(q.length < 2) { hideAc(); return; } try { const r = await fetch(BACKEND + "/api/public/catalogue/search?q=" + encodeURIComponent(q)); const d = await r.json(); if(r.ok && d.ok) renderAc(d.items || []); } catch(e) { hideAc(); } }
  function renderAc(items) { const dd = qs("autocompleteDropdown"); if(!items.length) { hideAc(); return; } dd.innerHTML = items.map(i => `<div class="ac-item" onclick="selectAcItem('${i.name.replace(/'/g,"\\'").replace(/"/g,"&quot;")}', ${i.estimatedPrice})"><div style="font-weight:900;">${i.name}</div><div class="mini">${i.category} • $${Number(i.estimatedPrice).toFixed(2)}</div></div>`).join(""); dd.style.display = "block"; }
  window.selectAcItem = function(name, price) { addGroceryItem(name, price); qs("itemSearchInput").value = ""; hideAc(); };
  function addGroceryItem(name, price) { currentGroceryList.push({ id: Math.random().toString(36).substr(2,9), name: name, price: Number(price) || 0 }); updateGroceryUI(); }
  window.removeGroceryItem = function(id) { currentGroceryList = currentGroceryList.filter(i => i.id !== id); updateGroceryUI(); };
  function updateGroceryUI() { const wrap = qs("groceryListItems"); if(!currentGroceryList.length) { wrap.innerHTML = ""; } else { wrap.innerHTML = currentGroceryList.map(i => `<div class="checkrow" style="justify-content:space-between; align-items:center;"><div><div style="font-weight:900;">${i.name}</div>${i.price > 0 ? `<div class="mini">$${i.price.toFixed(2)}</div>` : `<div class="mini">Custom / Unpriced</div>`}</div><button type="button" class="btn small ghost" onclick="removeGroceryItem('${i.id}')">Remove</button></div>`).join(""); } const total = currentGroceryList.reduce((sum, i) => sum + i.price, 0); qs("uiGroceryTotal").textContent = "$" + total.toFixed(2); qs("ord_grocerySubtotal").value = total.toFixed(2); qs("ord_groceryList").value = currentGroceryList.map(i => `• ${i.name}`).join("\n"); }

  function fillPrimaryStores(){ const sel = qs("ord_primaryStore"); const runType = qs("ord_runType").value || "local"; const current = sel.value; const items = STORES_BY_RUN[runType] || []; sel.innerHTML = '<option value="">Select…</option>'; items.forEach(item => { const o = document.createElement("option"); o.value = item; o.textContent = item; sel.appendChild(o); }); if (items.includes(current)) sel.value = current; }
  function addExtraStoreRow(value=""){ const wrap = qs("extraStoresWrap"); const card = document.createElement("div"); card.className = "storeCard"; card.innerHTML = `<div class="row" style="justify-content:space-between;"><div style="font-weight:1000;">Extra stop</div><button class="btn small ghost" type="button">Remove</button></div><label style="margin-top:10px;">Store / stop name</label><input placeholder="e.g., LCBO Wiarton, pharmacy, post office" value="${String(value).replace(/"/g, '&quot;')}" />`; card.querySelector("button").addEventListener("click", () => card.remove()); wrap.appendChild(card); }
  function getExtraStores(){ return qsa("#extraStoresWrap input").map(i => String(i.value || "").trim()).filter(Boolean); }
  function bindAddonToggle(chkId, detailsId){ const chk = qs(chkId); const details = qs(detailsId); if(chk && details) { const sync = () => details.classList.toggle("show", chk.checked); chk.addEventListener("change", sync); sync(); } }

  function updateOrderRunStatus(){ const el = qs("ord_runStatus"); const btn = qs("ord_submitBtn"); const rt = qs("ord_runType").value || "local"; if (!cachedRuns || !cachedRuns[rt]){ el.textContent = "Run info unavailable."; btn.disabled = true; return; } const rr = cachedRuns[rt]; el.textContent = `${rt.toUpperCase()} • ${rr.isOpen ? "OPEN ✅" : "CLOSED"} • Capacity Points: ${rr.bookedPoints || 0}/${rr.maxPoints || 10} • Cutoff: ${rr.cutoffAtLocal || "—"}`; btn.disabled = !rr.isOpen; }

  async function estimateOrderFees(){
    const msg = qs("ord_msg");
    try{
      const zone = qs("ord_zone").value; if (!zone) throw new Error("Select a zone first."); msg.textContent = "Estimating…";
      const r = await fetch(API_ESTIMATOR, { method:"POST", headers:{ "Content-Type":"application/json" }, body: JSON.stringify({ zone, runType: qs("ord_runType").value, memberTier: qs("ord_memberTier").value, applyPerk: "yes", extraStores: getExtraStores(), addon_printing: qs("addon_printing").checked ? "yes" : "no", printPages: Number(qs("addon_printPages").value || 0), grocerySubtotal: Number(qs("ord_grocerySubtotal").value || 0) }) });
      const d = await r.json().catch(()=>({})); if (!r.ok || d.ok === false) throw new Error(d.error || "Estimator failed");
      qs("ord_feePreview").textContent = "Estimated fees: " + dollars(d.breakdown?.totals?.totalFees ?? 0); msg.textContent = "Estimate updated ✅";
    } catch (e){ msg.textContent = String(e.message || e); }
  }

  function buildOrderGate(message, buttonText, action, showAccount=false){ qs("orderGate").style.display = ""; qs("orderGateMsg").textContent = message; qs("orderGateBtn").textContent = buttonText; qs("orderGateBtn").onclick = action; qs("orderGateGoAccount").style.display = showAccount ? "" : "none"; qs("orderGateGoAccount").onclick = () => selectTab("tab-account"); }
  function hideOrderGate(){ qs("orderGate").style.display = "none"; }

  async function loadProfile(){ if (!meCache.loggedIn){ profileCache = null; return null; } try{ const r = await fetch(API_PROFILE, { credentials:"include" }); const d = await r.json().catch(()=>({})); if (!r.ok || d.ok === false) return null; profileCache = d.profile || {}; return d; } catch { return null; } }

  function renderProfileSummary(){
    const strip = qs("orderProfileStrip"); if (!meCache.loggedIn || !profileCache || !Array.isArray(profileCache.addresses) || !profileCache.addresses.length){ strip.style.display = "none"; return; }
    strip.style.display = ""; const defaultId = String(profileCache.defaultId || ""); const addresses = profileCache.addresses || []; const selected = defaultId ? (addresses.find(a => String(a.id) === defaultId) || addresses[0]) : addresses[0];
    const name = profileCache.fullName || meCache.name || ""; const phone = profileCache.phone || "";
    qs("orderProfileSummary").textContent = `${name} • ${phone}${selected ? " • " + (selected.streetAddress || "") + ", " + (selected.town || "") + " " + (selected.postalCode || "") : ""}`;
    const sel = qs("ord_savedAddress"); sel.innerHTML = ""; addresses.forEach(a => { const o = document.createElement("option"); o.value = a.id; o.textContent = `${a.label || "Saved address"} — ${a.streetAddress || ""}, ${a.town || ""} ${a.postalCode || ""}`; sel.appendChild(o); });
    if (selected?.id) sel.value = selected.id;
  }

  function applySavedAddressToOrder(addressId){ if (!profileCache || !Array.isArray(profileCache.addresses)) return; const a = (profileCache.addresses || []).find(x => String(x.id) === String(addressId)) || profileCache.addresses[0]; if (!a) return; qs("ord_town").value = a.town || ""; qs("ord_street").value = a.streetAddress || ""; qs("ord_unit").value = a.unit || ""; qs("ord_postal").value = a.postalCode || ""; qs("ord_zone").value = a.zone || ""; }

  async function prefillOrderFromProfile(){
    if (!meCache.loggedIn || !profileCache) return;
    qs("ord_name").value = profileCache.fullName || meCache.name || ""; qs("ord_phone").value = profileCache.phone || ""; qs("ord_email").value = meCache.email || "";
    if (profileCache.contactPref) qs("ord_contactPref").value = profileCache.contactPref; if (profileCache.subsDefault) qs("ord_subsPref").value = profileCache.subsDefault; if (profileCache.dropoffDefault) qs("ord_dropoffPref").value = profileCache.dropoffDefault;
    if (meCache.membershipLevel && meCache.membershipLevel !== "none"){ qs("ord_memberTier").value = meCache.membershipLevel; }
    renderProfileSummary(); const selectedId = qs("ord_savedAddress").value || profileCache.defaultId || ""; if (selectedId) applySavedAddressToOrder(selectedId);
  }

  async function submitOrder(e){
    e.preventDefault(); const msg = qs("ord_msg"); const btn = qs("ord_submitBtn"); msg.textContent = "";
    try{
      await getMe();
      if (!meCache.loggedIn){ buildOrderGate("Sign-in required to place an order.", "Sign In", () => goLogin("https://tobermorygroceryrun.ca/?tab=account")); return; }
      if (!meCache.profileComplete){ buildOrderGate("Please complete Create Account first.", "Go to Create Account", () => selectTab("tab-account"), true); return; }
      hideOrderGate();

      if (!qs("consent_terms").checked || !qs("consent_accuracy").checked || !qs("consent_dropoff").checked) throw new Error("All required consents must be checked.");
      const groceryList = qs("ord_groceryList").value.trim(); if (!groceryList) throw new Error("Grocery list is empty.");
      if (!qs("ord_primaryStore").value.trim() || !qs("ord_zone").value.trim() || !qs("ord_town").value.trim() || !qs("ord_street").value.trim() || !qs("ord_postal").value.trim()) throw new Error("Please fill all required store and address fields.");

      btn.disabled = true; msg.textContent = "Authorizing payment… please wait.";

      // SECURE CARD TOKENIZATION
      let paymentSourceId = "";
      if (squareCard) {
        const result = await squareCard.tokenize();
        if (result.status === 'OK') {
          paymentSourceId = result.token;
        } else {
          throw new Error("Payment error: " + (result.errors[0]?.message || "Check card details."));
        }
      } else {
        throw new Error("Payment system not loaded. Please refresh.");
      }

      const fd = new FormData();
      fd.append("orderClass", "grocery"); fd.append("paymentSourceId", paymentSourceId);
      fd.append("fullName", qs("ord_name").value.trim()); fd.append("phone", qs("ord_phone").value.trim());
      fd.append("town", qs("ord_town").value.trim()); fd.append("streetAddress", qs("ord_street").value.trim()); fd.append("unit", qs("ord_unit").value.trim()); fd.append("postalCode", qs("ord_postal").value.trim()); fd.append("zone", qs("ord_zone").value.trim());
      fd.append("runType", qs("ord_runType").value.trim()); fd.append("primaryStore", qs("ord_primaryStore").value.trim()); fd.append("groceryList", groceryList);
      fd.append("dropoffPref", qs("ord_dropoffPref").value.trim()); fd.append("subsPref", qs("ord_subsPref").value.trim()); fd.append("contactPref", qs("ord_contactPref").value.trim());
      fd.append("consent_terms", "yes"); fd.append("consent_accuracy", "yes"); fd.append("consent_dropoff", "yes");
      fd.append("extraStores", JSON.stringify(getExtraStores())); fd.append("grocerySubtotal", String(Number(qs("ord_grocerySubtotal").value || 0))); fd.append("memberTier", qs("ord_memberTier").value || ""); fd.append("applyPerk", "yes");
      fd.append("dob", qs("ord_dob").value || ""); fd.append("altPhone", "");
      fd.append("addon_prescription", qs("addon_prescription").checked ? "yes" : "no"); fd.append("prescriptionPharmacy", qs("presc_pharmacy").value || ""); fd.append("prescriptionNotes", qs("presc_notes").value || "");
      fd.append("addon_liquor", qs("addon_liquor").checked ? "yes" : "no"); fd.append("liquorStore", qs("liq_store").value || ""); fd.append("liquorNotes", qs("liq_notes").value || "");
      fd.append("addon_printing", qs("addon_printing").checked ? "yes" : "no"); fd.append("printPages", String(Number(qs("addon_printPages").value || 0))); fd.append("printingNotes", qs("addon_printNotes").value || "");
      fd.append("addon_fastfood", qs("addon_fastfood").checked ? "yes" : "no"); fd.append("fastFoodRestaurant", qs("ff_rest").value || ""); fd.append("fastFoodOrder", qs("ff_order").value || "");
      fd.append("addon_parcel", qs("addon_parcel").checked ? "yes" : "no"); fd.append("parcelCarrier", qs("par_carrier").value || ""); fd.append("parcelDetails", qs("par_details").value || "");
      fd.append("addon_bulky", qs("addon_bulky").checked ? "yes" : "no"); fd.append("bulkyDetails", qs("bulky_notes").value || "");
      fd.append("optionalNotes", qs("ord_optionalNotes").value || "");
      fd.append("gateCode", qs("ord_gateCode").value || ""); fd.append("buildingAccessNotes", qs("ord_accessNotes").value || ""); fd.append("parkingNotes", qs("ord_parkingNotes").value || ""); fd.append("budgetCap", String(Number(qs("ord_budgetCap").value || 0))); fd.append("receiptPreference", qs("ord_receiptPref").value || ""); fd.append("photoProofOk", qs("ord_photoProofOk").checked ? "yes" : "no");
      const file = qs("ord_groceryFile").files?.[0]; if (file) fd.append("groceryFile", file, file.name);

      const r = await fetch(API_ORDERS, { method:"POST", body: fd, credentials:"include" });
      const d = await r.json().catch(()=>({}));
      if (!r.ok || d.ok === false) throw new Error(d.error || "Order failed");

      msg.textContent = `Order submitted ✅ Order ID: ${d.orderId}`;
      setTimeout(() => { window.location.href = BACKEND + "/member"; }, 900);
    } catch (e){ msg.textContent = String(e.message || e); } finally { btn.disabled = false; }
  }

  async function submitRide(e) {
    e.preventDefault(); const msg = qs("ride_msg"); const btn = qs("ride_submitBtn"); msg.textContent = "";
    try {
      await getMe();
      if (!meCache.loggedIn) { alert("Please Sign In or Create an Account first!"); goLogin("https://tobermorygroceryrun.ca/?tab=account"); return; }
      if (!qs("ride_consent").checked) throw new Error("Terms consent is required.");

      btn.disabled = true; msg.textContent = "Submitting Ride Request…";

      const fd = new FormData();
      fd.append("orderClass", "ride");
      fd.append("runType", qs("ride_runType").value); fd.append("ridePickup", qs("ride_pickup").value.trim()); fd.append("rideDestination", qs("ride_dest").value.trim()); fd.append("rideWindow", qs("ride_window").value.trim()); fd.append("rideNotes", qs("ride_notes").value.trim());
      fd.append("fullName", qs("ride_name").value.trim()); fd.append("phone", qs("ride_phone").value.trim()); fd.append("consent_terms", "yes"); fd.append("consent_accuracy", "yes");

      const r = await fetch(API_ORDERS, { method:"POST", body: fd, credentials:"include" });
      const d = await r.json().catch(()=>({}));
      if (!r.ok || d.ok === false) throw new Error(d.error || "Booking failed");

      msg.textContent = `Ride booked ✅ Order ID: ${d.orderId}`;
      setTimeout(() => { window.location.href = BACKEND + "/member"; }, 900);
    } catch (e) { msg.textContent = String(e.message || e); } finally { btn.disabled = false; }
  }

  function addressCardTemplate(address={}, isDefault=false){
    const uid = nextAcId("addr"); const lookupId = uid + "_lookup"; const labelId = uid + "_label"; const zoneId = uid + "_zone"; const townId = uid + "_town"; const postalId = uid + "_postal"; const streetId = uid + "_street"; const unitId = uid + "_unit"; const instructionsId = uid + "_instructions"; const gateId = uid + "_gate";
    const label = String(address.label || ""); const town = String(address.town || ""); const streetAddress = String(address.streetAddress || ""); const unit = String(address.unit || ""); const postalCode = String(address.postalCode || ""); const zone = String(address.zone || ""); const instructions = String(address.instructions || ""); const gateCode = String(address.gateCode || ""); const storedId = String(address.id || "");
    const wrapper = document.createElement("div"); wrapper.className = "addressCard"; wrapper.dataset.addrId = storedId || uid;
    wrapper.innerHTML = `<div class="row" style="justify-content:space-between;"><div style="font-weight:1000;">Saved address</div><div class="row"><label class="checkrow" style="padding:6px 10px; align-items:center;"><input type="radio" name="acc_default_address" ${isDefault ? "checked" : ""}><div class="mini" style="margin:0;">Default</div></label><button class="btn small ghost" type="button">Remove</button></div></div><label for="${lookupId}">Address lookup (Canada Post)</label><input id="${lookupId}" class="addr_lookup" placeholder="Start typing your street address" autocomplete="off" /><div class="mini">Selecting a suggestion fills street, unit, town, and postal code.</div><div class="row"><div class="col"><label for="${labelId}">Label</label><input id="${labelId}" class="addr_label" value="${label.replace(/"/g,'&quot;')}" placeholder="Home, cottage, rental" /></div><div class="col"><label for="${zoneId}">Zone<span class="req">*</span></label><select id="${zoneId}" class="addr_zone"><option value="">Select…</option><option value="A" ${zone==="A" ? "selected" : ""}>Zone A</option><option value="B" ${zone==="B" ? "selected" : ""}>Zone B</option><option value="C" ${zone==="C" ? "selected" : ""}>Zone C</option><option value="D" ${zone==="D" ? "selected" : ""}>Zone D</option></select></div></div><div class="row"><div class="col"><label for="${townId}">Town / City<span class="req">*</span></label><input id="${townId}" class="addr_town" list="townSuggestions" value="${town.replace(/"/g,'&quot;')}" placeholder="Town / city" /></div><div class="col"><label for="${postalId}">Postal Code<span class="req">*</span></label><input id="${postalId}" class="addr_postal" value="${postalCode.replace(/"/g,'&quot;')}" placeholder="N0H 2R0" /></div></div><div class="row"><div class="col"><label for="${streetId}">Street Address<span class="req">*</span></label><input id="${streetId}" class="addr_street" value="${streetAddress.replace(/"/g,'&quot;')}" placeholder="123 Main St" /></div><div class="col"><label for="${unitId}">Unit / Apt</label><input id="${unitId}" class="addr_unit" value="${unit.replace(/"/g,'&quot;')}" placeholder="Optional" /></div></div><label for="${instructionsId}">Delivery instructions</label><input id="${instructionsId}" class="addr_instructions" value="${instructions.replace(/"/g,'&quot;')}" placeholder="Optional" /><label for="${gateId}">Gate / buzzer code</label><input id="${gateId}" class="addr_gate" value="${gateCode.replace(/"/g,'&quot;')}" placeholder="Optional" />`;
    const removeBtn = wrapper.querySelector("button"); removeBtn.addEventListener("click", () => { wrapper.remove(); const cards = qsa("#acc_addresses .addressCard"); if (cards.length && !qsa('input[name="acc_default_address"]:checked').length){ cards[0].querySelector('input[type="radio"]').checked = true; } });
    return wrapper;
  }

  function addAddressCard(address={}, isDefault=false){ qs("acc_addresses").appendChild(addressCardTemplate(address, isDefault)); }

  function populateAccountForm(profile){
    qs("acc_fullName").value = profile?.fullName || meCache.name || ""; qs("acc_preferredName").value = profile?.preferredName || ""; qs("acc_phone").value = profile?.phone || ""; qs("acc_altPhone").value = profile?.altPhone || ""; qs("acc_contactPref").value = profile?.contactPref || ""; qs("acc_contactAuth").checked = !!profile?.contactAuth; qs("acc_subsDefault").value = profile?.subsDefault || ""; qs("acc_dropoffDefault").value = profile?.dropoffDefault || ""; qs("acc_notes").value = profile?.notes || ""; qs("acc_consentTerms").checked = !!profile?.consentTerms; qs("acc_consentPrivacy").checked = !!profile?.consentPrivacy; qs("acc_consentMarketing").checked = !!profile?.consentMarketing;
    qs("acc_addresses").innerHTML = ""; const addresses = Array.isArray(profile?.addresses) ? profile.addresses : []; const defId = String(profile?.defaultId || "");
    if (addresses.length){ addresses.forEach((a, idx) => addAddressCard(a, defId ? String(a.id) === defId : idx === 0)); } else { addAddressCard({}, true); }
  }

  function buildProfilePayload(){
    const cards = qsa("#acc_addresses .addressCard"); const checkedDefault = qsa('input[name="acc_default_address"]:checked')[0];
    const addresses = cards.map(card => { return { id: card.dataset.addrId || ("addr_" + Math.random().toString(36).slice(2, 10)), label: card.querySelector(".addr_label").value.trim(), town: card.querySelector(".addr_town").value.trim(), zone: card.querySelector(".addr_zone").value.trim(), streetAddress: card.querySelector(".addr_street").value.trim(), unit: card.querySelector(".addr_unit").value.trim(), postalCode: card.querySelector(".addr_postal").value.trim(), instructions: card.querySelector(".addr_instructions").value.trim(), gateCode: card.querySelector(".addr_gate").value.trim() }; });
    let defaultId = ""; if (checkedDefault){ const holder = checkedDefault.closest(".addressCard"); defaultId = holder?.dataset.addrId || ""; }
    return { fullName: qs("acc_fullName").value.trim(), preferredName: qs("acc_preferredName").value.trim(), phone: qs("acc_phone").value.trim(), altPhone: qs("acc_altPhone").value.trim(), contactPref: qs("acc_contactPref").value.trim(), contactAuth: qs("acc_contactAuth").checked ? "yes" : "no", subsDefault: qs("acc_subsDefault").value.trim(), dropoffDefault: qs("acc_dropoffDefault").value.trim(), customerType: "", accessibility: "", dietary: "", notes: qs("acc_notes").value.trim(), addresses, defaultId, consentTerms: qs("acc_consentTerms").checked ? "yes" : "no", consentPrivacy: qs("acc_consentPrivacy").checked ? "yes" : "no", consentMarketing: qs("acc_consentMarketing").checked ? "yes" : "no" };
  }

  async function saveProfile(e){
    e.preventDefault(); const msg = qs("acc_msg"); msg.textContent = "";
    try{
      await getMe();
      if (!meCache.loggedIn){ qs("acctGate").style.display = ""; qs("acctGateMsg").textContent = "Sign-in required to create an account."; qs("acctGateBtn").textContent = "Sign In"; qs("acctGateBtn").onclick = () => goLogin("https://tobermorygroceryrun.ca/?tab=account"); return; }
      const payload = buildProfilePayload();
      if (!payload.fullName || !payload.phone || !payload.contactPref) throw new Error("Please fill all required contact fields.");
      if (payload.contactAuth !== "yes") throw new Error("Authorize contact is required.");
      if (!payload.addresses.length) throw new Error("At least one saved address is required.");
      if (payload.addresses.find(a => !a.town || !a.zone || !a.streetAddress || !a.postalCode)) throw new Error("Each saved address must include town, zone, street address, and postal code.");
      if (payload.consentTerms !== "yes" || payload.consentPrivacy !== "yes") throw new Error("Terms and Privacy consents are required.");

      msg.textContent = "Saving profile…";
      const r = await fetch(API_PROFILE, { method:"POST", headers:{ "Content-Type":"application/json" }, credentials:"include", body: JSON.stringify(payload) });
      const d = await r.json().catch(()=>({}));
      if (!r.ok || d.ok === false) throw new Error(d.error || "Profile save failed");
      await getMe(); await loadProfile(); populateAccountForm(profileCache || {}); await prefillOrderFromProfile(); syncAccountTabVisibility();
      msg.textContent = "Profile saved ✅"; setTimeout(() => selectTab("tab-order"), 500);
    } catch (e){ msg.textContent = String(e.message || e); }
  }

  async function initOrderPanel(){
    await getMe();
    if (!meCache.loggedIn){ buildOrderGate("Sign in with Google first. Then you can create your profile and place an order.", "Sign In", () => goLogin("https://tobermorygroceryrun.ca/?tab=account")); return; }
    if (!profileCache) await loadProfile(); await prefillOrderFromProfile();
    if (!meCache.profileComplete){ buildOrderGate("Create your account once, save your profile, then the order form will auto-fill automatically.", "Go to Create Account", () => selectTab("tab-account"), true); } else { hideOrderGate(); }
    updateOrderRunStatus();
  }

  function bindOrderUI(){
    fillPrimaryStores();
    qs("ord_runType").addEventListener("change", () => { fillPrimaryStores(); updateOrderRunStatus(); });
    qs("ord_savedAddress").addEventListener("change", () => { applySavedAddressToOrder(qs("ord_savedAddress").value); });
    qs("ord_reloadProfile").addEventListener("click", async () => { await loadProfile(); await prefillOrderFromProfile(); });
    qs("ord_editProfile").addEventListener("click", () => { selectTab("tab-account"); });
    qs("btnAddStore").addEventListener("click", () => addExtraStoreRow("")); qs("btnClearStores").addEventListener("click", () => { qs("extraStoresWrap").innerHTML = ""; });
    qs("ord_calcFeesBtn").addEventListener("click", estimateOrderFees);
    qs("orderForm").addEventListener("submit", submitOrder);
    qs("rideForm").addEventListener("submit", submitRide);

    qs("itemSearchInput").addEventListener("input", (e) => { clearTimeout(acTimeout); acTimeout = setTimeout(() => doCatalogueSearch(e.target.value), 300); });
    qs("itemSearchInput").addEventListener("keydown", (e) => { if(e.key === "Enter") { e.preventDefault(); qs("btnAddItem").click(); } });
    qs("btnAddItem").addEventListener("click", () => { const val = qs("itemSearchInput").value.trim(); if(val) { addGroceryItem(val, 0); qs("itemSearchInput").value = ""; hideAc(); } });
    document.addEventListener("click", (e) => { if(!e.target.closest("#autocompleteDropdown") && e.target.id !== "itemSearchInput") hideAc(); });
    bindAddonToggle("addon_prescription", "prescDetails"); bindAddonToggle("addon_liquor", "liqDetails"); bindAddonToggle("addon_printing", "printDetails"); bindAddonToggle("addon_fastfood", "ffDetails"); bindAddonToggle("addon_parcel", "parcelDetails"); bindAddonToggle("addon_bulky", "bulkyDetails");
  }

  function bindAccountUI(){ qs("acc_addAddress").addEventListener("click", () => addAddressCard({}, false)); qs("acc_loadBtn").addEventListener("click", async () => { await loadProfile(); populateAccountForm(profileCache || {}); qs("acc_msg").textContent = "Loaded existing profile ✅"; }); qs("acctForm").addEventListener("submit", saveProfile); }

  function applyQueryTab(){
    const params = new URLSearchParams(window.location.search); const requested = (params.get("tab") || "").toLowerCase();
    const map = { home: "tab-home", about: "tab-about", pricing: "tab-pricing", areas: "tab-areas", estimator: "tab-estimator", order: "tab-order", ride: "tab-ride", account: "tab-account", memberships: "tab-memberships", faq: "tab-faq", contact: "tab-contact" };
    if (map[requested]){ selectTab(map[requested]); } else { selectTab("tab-home"); }
    if (params.get("onboarding") === "1" && meCache.loggedIn && meCache.profileComplete === false){ selectTab("tab-account"); }
  }

  async function boot(){
    qs("year").textContent = String(new Date().getFullYear());
    initOfflineBanner(); bindHeaderButtons(); bindEstimatorUI(); bindOrderUI(); bindAccountUI();
    await loadConfig(); initMembershipLinks(); await initAuthUI(); await loadRuns();
    if (meCache.loggedIn){ await loadProfile(); if (profileCache) { populateAccountForm(profileCache); await prefillOrderFromProfile(); } }
    applyQueryTab(); addExtraStoreRow(""); setInterval(loadRuns, 20000);
  }

  boot();
</script>
</body>
</html>
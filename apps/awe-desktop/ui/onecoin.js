(() => {
  "use strict";

  const view = document.getElementById("view");
  if (!view) return;

  const apiBase = () =>
    location.protocol === "http:" || location.protocol === "https:"
      ? location.origin
      : "http://127.0.0.1:41800";

  async function request(path, options) {
    const response = await fetch(apiBase() + path, {
      cache: "no-store",
      ...options
    });
    const body = await response.text();
    let data;
    try {
      data = JSON.parse(body);
    } catch (_) {
      throw new Error("The node returned an invalid response");
    }
    if (!response.ok) {
      throw new Error(data.error || body || ("HTTP " + response.status));
    }
    return data;
  }

  const get = (path) => request(path);
  const post = (path, value) => request(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(value)
  });

  const esc = (value) => String(value ?? "").replace(/[&<>'"]/g, (c) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "'": "&#39;",
    "\"": "&quot;"
  })[c]);

  function readCachedOffers() {
    try {
      const value = JSON.parse(localStorage.getItem("awenet.onecoin.offers") || "[]");
      return Array.isArray(value) ? value : [];
    } catch (_) {
      return [];
    }
  }

  function saveCachedOffers() {
    try {
      localStorage.setItem("awenet.onecoin.offers", JSON.stringify(offers));
    } catch (_) {
      // Storage can be disabled by the host browser; the node remains authoritative.
    }
  }

  let offers = readCachedOffers();
  let offerSource = "local cache";

  const tiers = [
    ["FREE", "No verified contribution", "Basic network access", "No automatic coin issuance"],
    ["BASIC", "Verified single-node capacity", "Storage, compute or bandwidth", "Policy-based; no guaranteed rate"],
    ["NET+", "Higher verified capacity", "Multiple resource types and availability", "Policy-based; no guaranteed rate"],
    ["NET PRO", "Verified multi-resource node", "Compute, storage and network capacity", "Requires signed usage evidence"],
    ["NET ULTRA", "Verified multi-node operator", "Coordinated nodes and availability", "Requires protocol support"],
    ["PRO", "Large-scale infrastructure", "Capacity subject to fair-use limits", "Requires protocol support"],
    ["DATA GROUP", "Coordinated resource group", "Group allocation and governance", "Governance capability required"],
    ["CENTRE GROUP", "Large coordinated infrastructure", "Data-centre capacity and governance", "Governance capability required"],
    ["AWENET USER", "Network participant", "AWEID and normal network access", "No infinite balance or resources"]
  ];

  function render() {
    const tierRows = tiers.map((tier) =>
      '<div class="tier-row"><div><b>' + esc(tier[0]) + '</b><small>' +
      esc(tier[1]) + '</small></div><span>' + esc(tier[2]) +
      '</span><strong>' + esc(tier[3]) + '</strong></div>'
    ).join("");

    view.innerHTML =
      '<div class="onecoin-hero"><div><div class="eyebrow">ONEBANK / ONECOIN</div>' +
      '<h1>Network economy</h1><p>Wallet transfers, exchange listings and transparent resource declarations.</p>' +
      '<div class="muted">Resource declarations are not verified rewards, and exchange listings do not move fiat money.</div>' +
      '</div><div class="coin-orb" aria-hidden="true">1C</div></div>' +
      '<div class="onecoin-grid">' +
      '<div class="card onecoin-stat"><div class="metric-label">Wallet balance</div><div id="ocBalance" class="metric">Connecting…</div><div id="ocOwner" class="muted">Loading AWE ID</div></div>' +
      '<div class="card onecoin-stat"><div class="metric-label">Resource tier</div><div id="ocTier" class="metric">Loading…</div><div id="ocContribution" class="muted">Contribution status unavailable</div></div>' +
      '<div class="card onecoin-stat"><div class="metric-label">Transfer fee</div><div id="ocFee" class="metric">1%</div><div class="muted">Current node policy</div></div>' +
      '<div class="card onecoin-stat"><div class="metric-label">Exchange</div><div class="metric">P2P</div><div class="muted">Fiat settlement is external</div></div>' +
      '</div>' +
      '<div class="onecoin-tabs" role="tablist">' +
      '<button class="oc-tab active" data-tab="wallet" role="tab">Wallet</button>' +
      '<button class="oc-tab" data-tab="exchange" role="tab">Exchange</button>' +
      '<button class="oc-tab" data-tab="rewards" role="tab">Resources</button>' +
      '<button class="oc-tab" data-tab="tiers" role="tab">Tiers</button>' +
      '<button id="ocRefresh" class="secondary" type="button">Refresh</button></div>' +
      '<section id="oc-wallet" class="oc-panel"><div class="section panel"><div class="section-head"><h2>Send ONECOIN</h2></div>' +
      '<div class="peer-form"><input id="ocRecipient" inputmode="text" autocomplete="off" placeholder="Recipient AWE ID (64 hex characters)" aria-label="Recipient AWE ID">' +
      '<input id="ocAmount" inputmode="decimal" placeholder="Amount, up to 9 decimal places" aria-label="ONECOIN amount">' +
      '<input id="ocMemo" maxlength="160" placeholder="Memo (optional)" aria-label="Transfer memo">' +
      '<button class="primary" id="ocSend" type="button">Send</button></div>' +
      '<div id="ocWalletState" class="notice" role="status">Transfers are validated by the local node. Check the transaction status before retrying.</div>' +
      '</div></section>' +
      '<section id="oc-exchange" class="oc-panel" hidden><div class="section panel"><div class="section-head"><h2>Create P2P offer</h2></div>' +
      '<div class="peer-form"><select id="ocSide" aria-label="Offer type"><option value="sell">Sell ONECOIN</option><option value="buy">Buy ONECOIN</option></select>' +
      '<input id="ocOfferAmount" type="number" min="0" step="0.000000001" placeholder="ONECOIN amount" aria-label="Offer amount">' +
      '<input id="ocPrice" type="number" min="0" step="0.01" placeholder="Fiat price per coin" aria-label="Fiat price per coin">' +
      '<select id="ocCurrency" aria-label="Fiat currency"><option>USD</option><option>EUR</option><option>AMD</option><option>GBP</option></select>' +
      '<select id="ocRail" aria-label="External payment method"><option>BankTransfer</option><option>ExternalPayment</option><option>Cash</option></select>' +
      '<button class="primary" id="ocOffer" type="button">Publish offer</button></div>' +
      '<div id="ocExchangeState" class="notice" role="status">Offers describe intent only. Verify the counterparty and settlement independently.</div></div>' +
      '<div class="section panel"><div class="section-head"><h2>Available offers</h2></div><div id="ocOffers"></div></div></section>' +
      '<section id="oc-rewards" class="oc-panel" hidden><div class="section panel"><div class="section-head"><h2>Resource declaration</h2></div>' +
      '<p class="muted">This saves a local declaration for diagnostics. The current API marks declarations unverified; this form does not credit ONECOIN.</p>' +
      '<div class="onecoin-form-grid"><input id="ocStorage" type="number" min="0" step="1" placeholder="Storage (GB)" aria-label="Storage in GB">' +
      '<input id="ocCpu" type="number" min="0" step="1" placeholder="CPU cores" aria-label="CPU cores">' +
      '<input id="ocRam" type="number" min="0" step="1" placeholder="RAM (GB)" aria-label="RAM in GB">' +
      '<input id="ocGpu" type="number" min="0" step="1" placeholder="GPU units" aria-label="GPU units">' +
      '<input id="ocBandwidth" type="number" min="0" step="0.1" placeholder="Bandwidth (TB/day)" aria-label="Bandwidth in TB per day">' +
      '<input id="ocUsage" type="number" min="0" max="100" step="1" placeholder="Utilization (%)" aria-label="Utilization percentage"></div>' +
      '<button class="primary" id="ocCalc" type="button">Save declaration</button>' +
      '<div id="ocCalcState" class="notice" role="status">No declaration submitted.</div></div></section>' +
      '<section id="oc-tiers" class="oc-panel" hidden><div class="section panel"><div class="section-head"><h2>Resource tiers</h2></div>' +
      '<p class="muted">Descriptions are indicative. Effective eligibility and any rewards must be determined by verified node policy.</p>' +
      '<div class="tier-list">' + tierRows + '</div></div></section>';

    bind();
    renderOffers();
    void loadWallet();
    void loadOffers();
  }

  function bind() {
    document.querySelectorAll(".oc-tab").forEach((button) => {
      button.onclick = () => {
        document.querySelectorAll(".oc-tab").forEach((tab) => tab.classList.toggle("active", tab === button));
        document.querySelectorAll(".oc-panel").forEach((panel) => { panel.hidden = true; });
        const target = document.getElementById("oc-" + button.dataset.tab);
        if (target) target.hidden = false;
      };
    });

    const refreshButton = document.getElementById("ocRefresh");
    if (refreshButton) refreshButton.onclick = () => {
      refreshButton.disabled = true;
      Promise.allSettled([loadWallet(), loadOffers()]).finally(() => { refreshButton.disabled = false; });
    };

    const sendButton = document.getElementById("ocSend");
    if (sendButton) sendButton.onclick = async () => {
      const state = document.getElementById("ocWalletState");
      const recipient = document.getElementById("ocRecipient").value.trim();
      const amount = document.getElementById("ocAmount").value.trim();
      const memo = document.getElementById("ocMemo").value.trim();
      if (!/^[0-9a-f]{64}$/i.test(recipient)) {
        state.textContent = "Enter a valid 64-character AWE ID.";
        return;
      }
      if (!/^(?:0|[1-9][0-9]*)(?:\.[0-9]{1,9})?$/.test(amount) || !amountToAtoms(amount)) {
        state.textContent = "Enter a positive amount with no more than 9 decimal places.";
        return;
      }
      sendButton.disabled = true;
      state.textContent = "Submitting the signed transfer to the local node…";
      try {
        const result = await post("/api/onebank/wallet/send", {
          recipient: recipient.toLowerCase(),
          amount_coins: amount,
          memo
        });
        if (result.status !== "accepted") throw new Error(result.error || "Transfer was not accepted");
        state.textContent = "Accepted by this node. Transaction: " + (result.tx_id || "ID unavailable") +
          (result.recipient_delivered ? " · Recipient delivery confirmed." :
            " · Recipient delivery is pending; acceptance is not delivery confirmation.");
        document.getElementById("ocAmount").value = "";
        await loadWallet();
      } catch (error) {
        state.textContent = "Transfer failed: " + error.message;
      } finally {
        sendButton.disabled = false;
      }
    };

    const offerButton = document.getElementById("ocOffer");
    if (offerButton) offerButton.onclick = async () => {
      const state = document.getElementById("ocExchangeState");
      const amount = document.getElementById("ocOfferAmount").value.trim();
      const price = document.getElementById("ocPrice").value.trim();
      if (!Number.isFinite(Number(amount)) || Number(amount) <= 0 ||
          !Number.isFinite(Number(price)) || Number(price) <= 0) {
        state.textContent = "Enter positive amount and price values.";
        return;
      }
      const offer = {
        id: (crypto.randomUUID ? crypto.randomUUID() : String(Date.now()) + "-" + Math.random().toString(16).slice(2)),
        side: document.getElementById("ocSide").value,
        amount,
        price,
        currency: document.getElementById("ocCurrency").value,
        rail: document.getElementById("ocRail").value
      };
      offerButton.disabled = true;
      try {
        const result = await post("/api/onebank/exchange/offers", offer);
        if (result.status !== "published") throw new Error(result.error || "Offer was not published");
        offers.unshift(result.offer || offer);
        offerSource = "node";
        saveCachedOffers();
        renderOffers();
        state.textContent = "Offer published to this node. No ONECOIN or fiat funds have moved.";
        document.getElementById("ocOfferAmount").value = "";
        document.getElementById("ocPrice").value = "";
      } catch (error) {
        offers.unshift({ ...offer, local_draft: true });
        offerSource = "local cache";
        saveCachedOffers();
        renderOffers();
        state.textContent = "Node publication failed (" + error.message + "). The offer is saved only as a local draft.";
      } finally {
        offerButton.disabled = false;
      }
    };

    const saveButton = document.getElementById("ocCalc");
    if (saveButton) saveButton.onclick = async () => {
      const state = document.getElementById("ocCalcState");
      const values = {
        storageGb: Number(document.getElementById("ocStorage").value) || 0,
        cpu: Number(document.getElementById("ocCpu").value) || 0,
        ramGb: Number(document.getElementById("ocRam").value) || 0,
        gpu: Number(document.getElementById("ocGpu").value) || 0,
        bandwidthTb: Number(document.getElementById("ocBandwidth").value) || 0,
        utilization: Number(document.getElementById("ocUsage").value) || 0
      };
      if (Object.values(values).some((value) => !Number.isFinite(value) || value < 0) ||
          values.utilization > 100 ||
          !Number.isInteger(values.cpu) || !Number.isInteger(values.gpu)) {
        state.textContent = "Use non-negative values; CPU and GPU must be whole numbers and utilization must be 0–100%.";
        return;
      }
      const storageBytes = Math.floor(values.storageGb * 1073741824);
      const ramBytes = Math.floor(values.ramGb * 1073741824);
      const bandwidthBytes = Math.floor(values.bandwidthTb * 1099511627776);
      if (![storageBytes, ramBytes, bandwidthBytes].every(Number.isSafeInteger)) {
        state.textContent = "A resource value is too large to represent safely.";
        return;
      }
      const declared = values.storageGb || values.cpu || values.ramGb || values.gpu || values.bandwidthTb;
      saveButton.disabled = true;
      state.textContent = "Saving the resource declaration…";
      try {
        const result = await post("/api/onebank/contribution", {
          storage_bytes: storageBytes,
          cpu_cores: values.cpu,
          ram_bytes: ramBytes,
          gpu_units: values.gpu,
          bandwidth_bytes: bandwidthBytes,
          online_hours: declared ? 24 : 0,
          node_count: declared ? 1 : 0,
          server_count: declared ? 1 : 0,
          uptime_bps: 10000,
          utilization_bps: Math.round(values.utilization * 100)
        });
        state.textContent = "Declaration saved. Verification: " + (result.verified ? "verified" : "not verified") +
          ". No coins were credited; signed usage receipts are required for rewards.";
        await loadWallet();
      } catch (error) {
        state.textContent = "Could not save declaration: " + error.message;
      } finally {
        saveButton.disabled = false;
      }
    };
  }

  function amountToAtoms(value) {
    if (!/^(?:0|[1-9][0-9]*)(?:\.[0-9]{1,9})?$/.test(value)) return 0n;
    const parts = value.split(".");
    const whole = BigInt(parts[0]);
    const fraction = BigInt(((parts[1] || "") + "000000000").slice(0, 9));
    return whole * 1000000000n + fraction;
  }

  function formatAtoms(value) {
    try {
      const atoms = BigInt(String(value ?? "0"));
      const whole = atoms / 1000000000n;
      const fractional = (atoms % 1000000000n).toString().padStart(9, "0").replace(/0+$/, "");
      return whole.toString() + (fractional ? "." + fractional : "") + " ONECOIN";
    } catch (_) {
      return "Balance unavailable";
    }
  }

  async function loadWallet() {
    try {
      const data = await get("/api/onebank/wallet");
      const balance = document.getElementById("ocBalance");
      const owner = document.getElementById("ocOwner");
      const tier = document.getElementById("ocTier");
      const contribution = document.getElementById("ocContribution");
      const fee = document.getElementById("ocFee");
      if (balance) balance.textContent = formatAtoms(data.balance_atoms_decimal ?? data.balance_atoms ?? "0");
      if (owner) owner.textContent = data.awe_id || "AWE ID unavailable";
      if (tier) tier.textContent = data.tier || "FREE";
      if (contribution) contribution.textContent =
        data.resource_verified ? "Verified contribution" : "Unverified · score " + (data.resource_score ?? "—");
      if (fee) fee.textContent = ((Number(data.fee_bps ?? 100) / 100).toFixed(2)).replace(/\.00$/, "") + "%";
    } catch (error) {
      const balance = document.getElementById("ocBalance");
      const owner = document.getElementById("ocOwner");
      if (balance) balance.textContent = "Ledger offline";
      if (owner) owner.textContent = "Could not load wallet: " + error.message;
    }
  }

  async function loadOffers() {
    try {
      const remote = await get("/api/onebank/exchange/offers");
      if (!Array.isArray(remote)) throw new Error("Unexpected offers response");
      offers = remote;
      offerSource = "node";
      saveCachedOffers();
    } catch (_) {
      offerSource = "local cache";
    }
    renderOffers();
  }

  function renderOffers() {
    const container = document.getElementById("ocOffers");
    if (!container) return;
    if (!offers.length) {
      container.innerHTML = '<div class="empty">No offers available. A local draft is not visible to other nodes.</div>';
      return;
    }
    container.innerHTML = offers.map((record) => {
      const offer = record && record.offer && !record.side ? record.offer : record;
      const local = record && record.local_draft;
      return '<div class="offer-row"><b>' + esc(String(offer.side || "OFFER").toUpperCase()) +
        '</b><span>' + esc(offer.amount ?? "—") + ' ONECOIN</span><span>' +
        esc(offer.price ?? "—") + ' ' + esc(offer.currency || "") + '/coin</span><span>' +
        esc(offer.rail || "External settlement") + '</span><small>' +
        (local || offerSource !== "node" ? "Local draft" : "Published on node") + '</small></div>';
    }).join("");
  }

  document.querySelectorAll(".nav").forEach((button) => {
    button.addEventListener("click", () => {
      if (button.dataset.view !== "onecoin") return;
      document.querySelectorAll(".nav").forEach((item) => item.classList.toggle("active", item === button));
      const title = document.getElementById("pageTitle");
      if (title) title.textContent = "ONECOIN";
      render();
    });
  });
})();
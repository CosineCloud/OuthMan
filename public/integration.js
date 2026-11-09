'use strict';
function integrationPanel() {
 const section = document.createElement('section');
 section.className='section integration';
 section.innerHTML=`<div class="section-head"><div><h2>Connect your apps</h2><p>A lightweight, backend-to-backend REST API. No SDK required.</p></div><span class="badge">API v1</span></div>
 <form id="app-form" class="invite-form"><label>Application name<input name="name" placeholder="XYZ app" maxlength="100" required></label><button type="submit" class="button">Create app credential</button></form><div id="app-credential" role="status"></div><div id="connected-apps" class="table-scroll"></div>
 <details open><summary>How registration and login work</summary><ol><li>Register the app here. Configure its app ID and secret in the XYZ backend environment.</li><li>The user first needs an OuthMan account. At XYZ registration, ask for their matching email/username, password, and a fresh OuthMan six-digit code.</li><li>XYZ backend calls <code>/api/v1/enroll</code>. Store the returned 128-bit <code>user_key</code> encrypted against the local user ID. Keep a password hash for XYZ login; never store a plaintext password. The enrollment code is consumed.</li><li>At login, validate the local password and ask for a new six-digit code. Generate a fresh random <code>request_id</code>, bind it to the pending login session, and call <code>/api/v1/verify</code> from the backend with all three user inputs and the stored user key.</li><li>OuthMan consumes the code and returns a random authentication PIN valid for 30 seconds. XYZ immediately calls <code>/api/v1/confirm</code> with that PIN, the same username and request ID.</li><li>Only create the XYZ session after confirmation returns <code>verified: true</code> and the returned app ID, immutable user ID, and request ID match the pending login. The PIN is consumed on confirmation.</li></ol><p class="notice">The per-user 128-bit key and authentication PIN travel only between backends. Never return them to the browser, include them in URLs or logs, or store them in localStorage. Use HTTPS outside localhost. Users must generate a new code after enrollment and after every successful verification.</p></details>
 <details><summary>REST / curl examples</summary><p>Run only on the XYZ server. Replace placeholders using a JSON serializer in your application. Requests need no OuthMan browser session or cookies.</p><div id="curl-examples"></div><p>All bodies are JSON. Codes are strings so leading zeroes are preserved. A key is 32 hexadecimal characters (128 bits). A six-digit code expires after 60 seconds; a PIN after 30 seconds. Revoking an app disables all of its linked accounts and pending PINs.</p></details>
 <details><summary>Responses and error handling</summary><p><code>enroll → 201 {app_id, user_id, username, user_key}</code><br><code>verify → 200 {auth_pin, expires_at, request_id}</code><br><code>confirm → 200 {verified: true, app_id, user_id, username, request_id}</code></p><p>400 invalid input · 401 verification failed, expired or consumed · 409 already linked · 429 too many failed requests (retry after 15 minutes). Fail closed on every non-success response, timeout, or network error. Never grant login from the verify response alone. If a response is lost after consumption, ask for a fresh code; do not retry the old code. Existing links cannot be re-enrolled to retrieve their secret.</p><p>IP and browser audit values describe the calling XYZ backend for API requests. They do not identify the end user's browser or IP.</p></details>`;
 app.querySelector('.reveal').append(section);
 if(!integrationAvailable){
  section.querySelector('#app-form').hidden=true;
  section.querySelector('#app-credential').innerHTML='<p class="warning" role="alert">The running OuthMan server does not support API v1 yet. Stop it with Ctrl+C, run python3 server.py again, then refresh this page.</p>';
 }
 const base=location.origin;
 const examples=[
 ['1. Enroll once at XYZ registration', 'enroll', {username:'person@example.com',password:'USER_PASSWORD',code:'012345'}],
 ['2. Verify each login with a fresh code', 'verify', {username:'person@example.com',password:'USER_PASSWORD',code:'654321',user_key:'STORED_128_BIT_USER_KEY',request_id:'FRESH_RANDOM_LOGIN_REQUEST_ID'}],
 ['3. Confirm the returned PIN before granting login', 'confirm', {username:'person@example.com',auth_pin:'PIN_FROM_VERIFY',request_id:'SAME_LOGIN_REQUEST_ID'}]
 ];
 document.querySelector('#curl-examples').innerHTML=examples.map(([title,path,body])=>`<h3>${esc(title)}</h3><pre><code>${esc(`curl --fail-with-body '${base}/api/v1/${path}' \\\n  -H 'Content-Type: application/json' \\\n  -H 'X-OuthMan-App: YOUR_APP_ID' \\\n  -H 'Authorization: Bearer YOUR_APP_SECRET' \\\n  --data '${JSON.stringify(body)}'`)}</code></pre>`).join('');
 document.querySelector('#app-form').addEventListener('submit',e=>{e.preventDefault();submit(e.target,async data=>{
  const result=await api('apps',{name:data.get('name')});
  document.querySelector('#app-credential').innerHTML=`<div class="notice"><strong>Configure these in the XYZ backend now. The secret is shown only once.</strong><p>App ID: <code>${esc(result.app_id)}</code><br>App secret: <code>${esc(result.app_secret)}</code></p><button type="button" class="button secondary" id="hide-app-secret">Hide credential</button></div>`;
  document.querySelector('#hide-app-secret').addEventListener('click',()=>document.querySelector('#app-credential').replaceChildren());
  await loadAdmin();
 });});
}
function renderApps(apps) {
 const el=document.querySelector('#connected-apps');if(!el)return;if(!integrationAvailable){el.replaceChildren();return;}
 el.innerHTML=apps.length?`<table><thead><tr><th>App</th><th>ID</th><th>Status</th><th>Action</th></tr></thead><tbody>${apps.map(a=>`<tr><td>${esc(a.name)}</td><td><code>${esc(a.id)}</code></td><td>${a.revoked_at?'Revoked':'Active'}</td><td>${a.revoked_at?'—':`<button class="button secondary revoke-app" data-app="${esc(a.id)}">Revoke</button>`}</td></tr>`).join('')}</tbody></table>`:'<p class="empty">No connected apps. Create a credential above to begin.</p>';
 el.querySelectorAll('.revoke-app').forEach(button=>button.addEventListener('click',async()=>{if(!confirm('Revoke this app? All its OuthMan integrations will stop working.'))return;button.disabled=true;try{await api('apps/revoke',{app_id:button.dataset.app});await loadAdmin();}catch(e){toast(e.message);button.disabled=false;}}));
}

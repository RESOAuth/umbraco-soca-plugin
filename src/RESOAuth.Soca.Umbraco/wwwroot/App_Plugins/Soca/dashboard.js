import { LitElement, html, css } from '@umbraco-cms/backoffice/external/lit';
import { UmbElementMixin } from '@umbraco-cms/backoffice/element-api';
import { UMB_AUTH_CONTEXT } from '@umbraco-cms/backoffice/auth';

class SocaDashboard extends UmbElementMixin(LitElement) {
  static properties = { profiles: {state: true}, message: {state: true} };
  static styles = css`:host {display:block;padding:24px} uui-box {margin-block-end:16px} button {margin:8px}`;
  constructor() {
    super(); this.profiles = []; this.message = '';
    this.consumeContext(UMB_AUTH_CONTEXT, context => { this.auth = context; this.load(); });
  }
  async request(path = '', method = 'GET') {
    const token = await this.auth.getLatestToken();
    const response = await fetch('/umbraco/management/api/v1/soca' + path, {method, headers: {Authorization: `Bearer ${token}`}});
    if (!response.ok) throw new Error('SOCA operation failed. Check deployment configuration and operator access.');
    return response.json();
  }
  async load() { try {this.profiles = await this.request();} catch (error) {this.message = error.message;} }
  async action(profile, action) {
    try {
      const result = await this.request(`/${profile.name}/${profile.surface}/${action}`, 'POST');
      if (action === 'test' && result.url) window.location.assign(result.url);
      else {this.message = 'Public documents checked. Complete a real candidate login before enabling this profile.'; await this.load();}
    } catch (error) {this.message = error.message;}
  }
  render() {
    return html`<uui-box headline="SOCA provider configuration">
      <p>Settings are deployment-managed and read-only here. Each protected surface uses separate callbacks, native associations and evidence. Local login remains available.</p>
      <p role="status" aria-live="polite">${this.message}</p>
      ${this.profiles.map(profile => html`<uui-box headline=${profile.name + ' / ' + profile.surface}>
        <dl><dt>Public client ID</dt><dd>${profile.clientId}</dd><dt>Document check</dt><dd>${profile.documentChecked ? 'Passed' : 'Required'}</dd><dt>Real candidate login</dt><dd>${profile.liveTestPassed ? 'Passed' : 'Required'}</dd><dt>Emergency disable</dt><dd>${profile.emergencyDisabled ? 'Enabled' : 'Off'}</dd></dl>
        <uui-button label="Check public documents" @click=${() => this.action(profile, 'check')}></uui-button>
        <uui-button label="Test candidate login" @click=${() => this.action(profile, 'test')}></uui-button>
      </uui-box>`)}
    </uui-box>`;
  }
}
customElements.define('soca-dashboard', SocaDashboard);

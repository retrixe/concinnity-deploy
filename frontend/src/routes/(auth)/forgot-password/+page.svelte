<script lang="ts">
  import Button from '$lib/components/Button.svelte'
  import TextInput from '$lib/components/TextInput.svelte'

  let usenameEmail = $state('')
  let disabled = $state(false)
  let error: string | null = $state(null)

  const clearError = () => (error = null)

  function onForgotPassword() {
    disabled = true
    try {
      /* const res = await ky
        .post(`api/login`, { json: usenameEmail })
        .json<{ token: string; username: string }>()
      localStorage.setItem('concinnity:token', res.token) */
      error = ''
    } catch (e: unknown) {
      error =
        e instanceof Error ? e.message : (e?.toString() ?? `Failed to send reset password e-mail!`)
    }
    disabled = false
  }
</script>

<h2>Forgot your password?</h2>
<br />
<p class="left-align">
  No worries! Enter your email address and we will send you a link to reset your password.
</p>
<br />
<label for="forgot-password-username-email">Username / E-mail</label>
<TextInput
  id="forgot-password-username-email"
  bind:value={usenameEmail}
  oninput={clearError}
  error={!!error}
  {disabled}
  type="email"
  placeholder="e.g. aelia@retrixe.xyz"
  onkeypress={e => e.key === 'Enter' && onForgotPassword() /* eslint-disable-line */}
/>
{#if error === ''}
  <p class="result">Sent reset link successfully! Keep an eye on your e-mail...</p>
{:else if !!error}
  <p class="result error">{error}</p>
{/if}
<br />
<Button {disabled} onclick={onForgotPassword}>Send E-mail</Button>
<br />
<p>Want to try logging in? <a href="/login">Log in</a></p>

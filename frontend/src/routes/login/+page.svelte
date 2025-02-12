<script lang="ts">
  import { goto, invalidate } from '$app/navigation'
  import { page } from '$app/state'
  import ky from '$lib/api/ky'
  import Box from '$lib/components/Box.svelte'
  import Button from '$lib/components/Button.svelte'
  import TextInput from '$lib/components/TextInput.svelte'

  let login = $state({ username: '', password: '' })
  let disabled = $state(false)
  let error: string | null = $state(null)

  const { username } = $derived(page.data)
  $effect(() => {
    if (username) goto('/').catch(console.error)
  })

  async function onLogin() {
    disabled = true
    try {
      const res = await ky
        .post(`api/login`, { json: login })
        .json<{ token: string; username: string }>()
      localStorage.setItem('concinnity:token', res.token)
      error = ''
    } catch (e: unknown) {
      error = e instanceof Error ? e.message : (e?.toString() ?? `Failed to login!`)
    }
    disabled = false
    if (!error) {
      invalidate('app:auth').catch(console.error)
    }
  }
</script>

<div class="container">
  <Box>
    <h2>Login</h2>
    <br />
    <label for="login-username">E-mail / Username</label>
    <TextInput
      id="login-username"
      bind:value={login.username}
      error={!!error}
      {disabled}
      type="email"
      placeholder="e.g. aelia@retrixe.xyz"
    />
    <label for="login-password">Password</label>
    <TextInput
      id="login-password"
      bind:value={login.password}
      error={!!error}
      {disabled}
      type="password"
      onkeypress={e => e.key === 'Enter' && onLogin() /* eslint-disable-line */}
    />
    {#if error === ''}
      <p class="result">Logged in successfully! You should be redirected shortly...</p>
    {:else if !!error}
      <p class="result error">{error}</p>
    {/if}
    <br />
    <Button {disabled} onclick={onLogin}>Login</Button>
    <br />
    <p>Don't have an account? <a href="/register">Sign up</a></p>
  </Box>
</div>

<style lang="scss">
  .error {
    color: var(--error-color);
  }

  label {
    padding: 0.5rem 0rem;
    font-weight: bold;
  }

  p {
    align-self: center;
  }

  .container > :global(div) {
    display: flex;
    flex-direction: column;
    padding: 1.5rem;
    margin: 1.5rem;
    width: 100%;
    max-width: 400px;
  }

  .container {
    flex-grow: 1;
    display: flex;
    justify-content: center;
    align-items: center;
  }
</style>

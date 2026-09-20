import { Controller, Get, Query, Res } from '@nestjs/common';
import type { FastifyReply } from 'fastify';
import { renderPage, type PageOptions } from './page';

// One parameterized route rather than ~10 near-identical ones — every
// terminal OAuth outcome shares the same structure (icon, heading,
// message, optional return-to-KIS handoff), only the copy differs.
// Keyed by the same vocabulary oauth.controller.ts's redirects use.
const STATES: Record<
  string,
  Pick<PageOptions, 'title' | 'heading' | 'message' | 'tone'>
> = {
  success: {
    title: 'Signed in',
    heading: 'Authentication successful',
    message: "You're verified with Google. Returning you to KIS…",
    tone: 'success',
  },
  recovery_success: {
    title: 'Account recovered',
    heading: 'Your KIS account has been verified',
    message: 'You can now continue using KIS on this device.',
    tone: 'success',
  },
  registration_continue: {
    title: 'Almost there',
    heading: 'Google account verified',
    message: 'Finishing your KIS account setup — returning you to the app…',
    tone: 'success',
  },
  cancelled: {
    title: 'Cancelled',
    heading: 'Sign-in was cancelled',
    message: 'You closed or cancelled Google sign-in. No changes were made to your account.',
    tone: 'neutral',
  },
  not_linked: {
    title: 'Account not linked',
    heading: "This Google account isn't linked to a KIS account",
    message:
      'To use Google sign-in for recovery, first log in to KIS the usual way and link your Google account from Settings.',
    tone: 'neutral',
  },
  already_linked: {
    title: 'Already linked',
    heading: 'This Google account is already linked',
    message: "It's already connected to a different KIS account. Sign in to that account instead.",
    tone: 'error',
  },
  already_registered: {
    title: 'Already registered',
    heading: 'You already have a KIS account',
    message: 'This Google account is already associated with a KIS account. Try signing in instead of signing up.',
    tone: 'neutral',
  },
  expired: {
    title: 'Session expired',
    heading: 'This sign-in session expired',
    message: 'For your security, sign-in sessions time out after a few minutes. Please try again.',
    tone: 'error',
  },
  rate_limited: {
    title: 'Too many attempts',
    heading: 'Please try again shortly',
    message: 'Too many attempts in a short time. Wait a minute and try again.',
    tone: 'error',
  },
  invalid_request: {
    title: 'Something went wrong',
    heading: "We couldn't complete this request",
    message: 'Please return to KIS and try again.',
    tone: 'error',
  },
  server_error: {
    title: 'Temporary error',
    heading: 'Something went wrong on our end',
    message: "This wasn't caused by anything you did. Please try again in a moment.",
    tone: 'error',
  },
};

@Controller()
export class WebController {
  @Get()
  async welcome(@Res({ passthrough: true }) res: FastifyReply) {
    res.header('Content-Type', 'text/html; charset=utf-8');
    return renderPage({
      title: 'Welcome',
      heading: 'KIS Auth',
      message:
        'Secure authentication for Kingdom Impact Social. Open this from the KIS app to sign in or recover your account with Google — this page has nothing to do on its own.',
      tone: 'neutral',
    });
  }

  @Get('status')
  async status(
    @Query('state') state: string | undefined,
    // The COMPLETE target URL — already carrying whatever query params the
    // client needs (code+state on success, error+state on failure).
    // Never reconstructed here, so there's no risk of this route
    // duplicating or clobbering a param the caller already set.
    @Query('client_redirect') clientRedirect: string | undefined,
    @Res({ passthrough: true }) res: FastifyReply,
  ) {
    const copy = (state && STATES[state]) || STATES.invalid_request;

    let returnTo: PageOptions['returnTo'];
    if (clientRedirect) {
      try {
        // Validate it parses as a real absolute URL before ever handing
        // it back as a link/auto-redirect target — this endpoint's input
        // is caller-controlled, even though every current caller is our
        // own oauth.controller.ts using an already-validated session
        // redirect_uri.
        const target = new URL(clientRedirect);
        returnTo = { url: target.toString(), label: 'Return to KIS' };
      } catch {
        // Malformed client_redirect — show the message with no handoff
        // rather than build a broken/unsafe link.
      }
    }

    res.header('Content-Type', 'text/html; charset=utf-8');
    return renderPage({ ...copy, returnTo });
  }
}

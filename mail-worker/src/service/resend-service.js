import emailService from './email-service';
import { emailConst } from '../const/entity-const';

function webhookParams(body) {
	const resendEmailId = body?.data?.email_id;
	if (!resendEmailId) {
		return null;
	}

	const params = {
		resendEmailId,
		status: emailConst.status.SENT
	}

	if (body.type === 'email.sent') {
		return params;
	}

	if (body.type === 'email.delivered') {
		params.status = emailConst.status.DELIVERED
		params.message = null
		return params;
	}

	if (body.type === 'email.complained') {
		params.status = emailConst.status.COMPLAINED
		params.message = null
		return params;
	}

	if (body.type === 'email.bounced') {
		params.status = emailConst.status.BOUNCED
		params.message = JSON.stringify(body.data.bounce);
		return params;
	}

	if (body.type === 'email.delivery_delayed') {
		params.status = emailConst.status.DELAYED
		params.message = null
		return params;
	}

	if (body.type === 'email.failed') {
		params.status = emailConst.status.FAILED
		params.message = body.data.failed?.reason
		return params;
	}

	return null;
}

const resendService = {

	async webhooks(c, body) {

		const params = webhookParams(body);
		if (!params) {
			console.warn(`Ignored unsupported Resend webhook event: ${body?.type}`);
			return;
		}

		const emailRow = await emailService.updateEmailStatus(c, params)

		if (!emailRow) {
			console.warn(`Ignored Resend webhook for unknown email id: ${params.resendEmailId}`);
		}

	}
}

export default resendService

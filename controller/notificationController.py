import json
import logging
from pywebpush import webpush, WebPushException
from response_maker import responseMaker
from database.dbcon import dbGetRMeLOG, dbTransRMeLOG, prepareJson
from config import VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY, VAPID_CLAIM

def getVAPIDPublicKey():
    return VAPID_PUBLIC_KEY

def routeGetNotifications(RM_UserId):
    data, rows, cols = dbGetRMeLOG("""
        EXEC [dbo].[fsp_ReadNotifications] 
        @RM_UserId=?
        """,
        RM_UserId)
    return responseMaker(prepareJson(rows, cols), "success", 200, "NotificationList")

def routeMarkNotifications(Id):
    resp = dbTransRMeLOG("""
        EXEC fsp_UpdateNotifications 
            @Id = ?
        """, Id)
    return resp

def routePWASubscribe(RM_UserId, endpoint, p256dh_key, auth_key, expirationTime=None):
    resp = dbTransRMeLOG("""
        EXEC [notifications].[fsp_PWASubscribe]
            @RM_UserId = ?,
            @Endpoint = ?,
            @P256dhKey = ?,
            @AuthKey = ?,
            @ExpirationTime = ?
    """, RM_UserId, endpoint, p256dh_key, auth_key, expirationTime)
    return resp

def routePWAUnsubscribe(endpoint):
    resp = dbTransRMeLOG("""
        EXEC [notifications].[fsp_PWAUnsubscribe]
            @Endpoint = ?
    """, endpoint)
    return resp

def routePWAGetSubscriptions(RM_UserId=None):
    data, rows, cols = dbGetRMeLOG("""
        EXEC [notifications].[fsp_PWAGetSubscriptions]
            @RM_UserId = ?
    """, RM_UserId)
    return responseMaker(prepareJson(rows, cols), "success", 200, "Subscriptions")

def routePWAMarkInactive(endpoint):
    resp = dbTransRMeLOG("""
        EXEC [notifications].[fsp_PWAMarkInactive]
            @Endpoint = ?
    """, endpoint)
    return resp

def routeGetNotificationsToNotify():
    data, rows, cols = dbGetRMeLOG("""
        EXEC [notifications].[ToNotify]
    """)
    return prepareJson(rows, cols)

def _get_subscriptions_for_user(rm_user_id):
    try:
        result = routePWAGetSubscriptions(rm_user_id)
        if hasattr(result, 'get_json'):
            data = result.get_json()
        elif isinstance(result, dict):
            data = result
        else:
            return []
        
        subscriptions = data.get('Subscriptions') or data.get('data', []) or []
        return subscriptions if isinstance(subscriptions, list) else []
    except:
        return []

def _convert_to_webpush_format(subscriptions_list):
    webpush_subs = []
    for sub in subscriptions_list:
        if not isinstance(sub, dict):
            continue
        if sub.get('is_active') not in [1, True]:
            continue
        
        endpoint = sub.get('endpoint', '')
        p256dh = sub.get('p256dh_key', '')
        auth = sub.get('auth_key', '')
        
        if endpoint and p256dh and auth:
            webpush_subs.append({
                'endpoint': endpoint,
                'keys': {'p256dh': p256dh, 'auth': auth}
            })
    return webpush_subs

def sendPWANotification():
    try:
        notifications = routeGetNotificationsToNotify()
        if notifications is None:
            notifications = []
        elif not isinstance(notifications, list):
            notifications = []
        if not notifications:
            return {
                'notifications_processed': 0,
                'notifications_sent': 0,
                'notifications_failed': 0,
                'subscriptions_notified': 0,
                'errors': [],
                'status': 'success',
                'code': 200,
                'message': 'No notifications to send'
            }
        results = {
            'notifications_processed': 0,
            'notifications_sent': 0,
            'notifications_failed': 0,
            'subscriptions_notified': 0,
            'errors': []
        }
        successful_notification_ids = []  # Will be marked as IsNotified=1
        no_subscription_ids = []  # Will be marked as IsNotified=2 (no subscription/skipped)
        for notif in notifications:
            notif_id = notif.get('Id')
            rm_user_id = notif.get('RM_UserId')
            subscriptions_list = _get_subscriptions_for_user(rm_user_id)
            subscriptions_to_notify = _convert_to_webpush_format(subscriptions_list)
            if not subscriptions_to_notify:
                results['notifications_failed'] += 1
                results['notifications_processed'] += 1
                # Mark as skipped (no subscription) - prevents infinite retry
                no_subscription_ids.append(str(notif_id))
                continue
            notification_data = {
                'title': notif.get('Title', 'Notification'),
                'body': notif.get('NotificationMessage', 'You have a new notification'),
                'icon': '/pwa-192x192.png',
                'badge': '/pwa-64x64.png',
                'data': {
                    'notificationId': notif_id,
                    'submissionId': notif.get('SubmissionId'),
                    'rmUserId': rm_user_id,
                    'url': '/notification/' + str(notif_id) if notif_id else None
                }
            }
            success_count = 0
            for subscription in subscriptions_to_notify:
                try:
                    webpush(
                        subscription_info=subscription,
                        data=json.dumps(notification_data),
                        vapid_private_key=VAPID_PRIVATE_KEY,
                        vapid_claims={
                            "sub": VAPID_CLAIM
                        }
                    )
                    success_count += 1
                    results['subscriptions_notified'] += 1
                except WebPushException as e:
                    results['errors'].append(f"Notification {notif_id}: {str(e)}")
                    if e.response and e.response.status_code == 410:
                        endpoint = subscription.get('endpoint', '')
                        routePWAMarkInactive(endpoint)
                except Exception as e:
                    results['errors'].append(f"Notification {notif_id}: {str(e)}")
            results['notifications_processed'] += 1
            if success_count > 0:
                results['notifications_sent'] += 1
                successful_notification_ids.append(str(notif_id))
            else:
                results['notifications_failed'] += 1
        # Mark successful notifications as IsNotified=1
        if successful_notification_ids:
            try:
                routeMarkIsNotified(','.join(successful_notification_ids), 1)
            except Exception as mark_err:
                results['errors'].append(f"Failed to mark notifications as sent")
        # Mark no-subscription notifications as IsNotified=2 (skipped - prevents infinite retry)
        if no_subscription_ids:
            try:
                routeMarkIsNotified(','.join(no_subscription_ids), 2)
            except Exception as mark_err:
                results['errors'].append(f"Failed to mark skipped notifications")
        results['status'] = 'success' if results['notifications_sent'] > 0 else 'error'
        results['code'] = 200 if results['notifications_sent'] > 0 else 500
        return results
    except Exception as e:
        logging.error(f"Errror in sendPWANotification {e}")
        return {
            'notifications_processed': 0,
            'notifications_sent': 0,
            'notifications_failed': 0,
            'subscriptions_notified': 0,
            'errors': ['An internal Error occured'],
            'status': 'error',
            'code': 500
        }

def routeMarkIsNotified(Id, Status=1):
    """
    Mark notifications with given status.
    Status: 1 = Notified (success), 2 = Skipped (no subscription)
    """
    resp = dbTransRMeLOG("""
        EXEC [notifications].[MarkNotify]
            @Id = ?,
            @Status = ?
        """, Id, Status)
    return resp

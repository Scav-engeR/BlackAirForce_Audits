# Python Version v12 above

from pyrogram import Client, filters
from pyrogram.types import Message, InlineKeyboardMarkup, InlineKeyboardButton, CallbackQuery
from datetime import datetime
import pytz
from config import ADMIN_ID # Just import your ADMIN ID from your .env
from decorator import track_user
import logging

logger = logging.getLogger(__name__)

# Store suggestion data temporarily
suggestion_data = {}

@track_user
async def suggest_command(client: Client, message: Message):
    """Handle /suggest command"""
    try:
        # Check if user provided a suggestion message
        if len(message.command) < 2:
            await message.reply_text(
                "❌ **Please provide a suggestion message!**\n\n"
                "**Usage:** `/suggest <your suggestion message>`\n\n"
                "**Example:** `/suggest Please add a weather feature to the bot`"
            )
            return
        
        # Extract suggestion message
        suggestion_text = message.text.split(None, 1)[1]
        
        # Get user information
        user_id = message.from_user.id
        username = message.from_user.username or "No Username"
        first_name = message.from_user.first_name or "Unknown"
        
        # Get current time in PHT timezone
        pht_tz = pytz.timezone('Asia/Manila') # Change depending on your location
        current_time = datetime.now(pht_tz)
        formatted_date = current_time.strftime("%m/%d/%Y")
        formatted_time = current_time.strftime("%I:%M %p")
        
        # Store suggestion data with initial status
        suggestion_id = f"{user_id}_{int(current_time.timestamp())}"
        suggestion_data[suggestion_id] = {
            'user_id': user_id,
            'username': username,
            'first_name': first_name,
            'message': suggestion_text,
            'date': formatted_date,
            'time': formatted_time,
            'full_datetime': current_time,
            'status': 'New 🆕'  # Initial status with emoji
        }
        
        # Send thank you message to user
        thank_you_msg = (
            "🙏 **Thank you for your valuable suggestion!**\n\n"
            "✨ We truly appreciate your feedback and suggestions. "
            "Your input helps us maintain excellence in our work and "
            "continuously improve our services.\n\n"
            "📝 Your suggestion has been forwarded to our admin team "
            "and will be carefully reviewed.\n\n"
            "🚀 We're committed to providing the best experience possible!"
        )
        
        await message.reply_text(thank_you_msg)
        
        # Create notification message for admin
        notification_msg = (
            "📬 **New Suggestion Received!**\n\n"
            "💡 A user has submitted a new suggestion for the bot.\n"
            "📅 **Received:** Today\n\n"
            "Click the buttons below to manage this suggestion:"
        )
        
        # Create inline keyboard for admin
        keyboard = InlineKeyboardMarkup([
            [
                InlineKeyboardButton("📖 Read", callback_data=f"read_suggestion:{suggestion_id}"),
                InlineKeyboardButton("💬 Feedback", callback_data=f"feedback_suggestion:{suggestion_id}")
            ],
            [
                InlineKeyboardButton("Done ✅", callback_data=f"done_suggestion:{suggestion_id}")
            ]
        ])
        
        # Send notification to admin
        try:
            await client.send_message(
                chat_id=ADMIN_ID,
                text=notification_msg,
                reply_markup=keyboard
            )
            logger.info(f"Suggestion notification sent to admin for user {user_id}")
        except Exception as e:
            logger.error(f"Failed to send suggestion to admin: {e}")
            await message.reply_text("⚠️ There was an issue forwarding your suggestion. Please try again later.")
            
    except Exception as e:
        logger.error(f"Error in suggest command: {e}")
        await message.reply_text("❌ An error occurred while processing your suggestion. Please try again.")

async def handle_suggestion_callbacks(client: Client, callback_query: CallbackQuery):
    """Handle callback queries for suggestion management"""
    try:
        data = callback_query.data
        
        if data.startswith("read_suggestion:"):
            suggestion_id = data.split(":", 1)[1]
            
            if suggestion_id not in suggestion_data:
                await callback_query.answer("❌ Suggestion data not found!", show_alert=True)
                return
            
            suggestion = suggestion_data[suggestion_id]
            
            # Format the suggestion message with status
            suggestion_msg = (
                f"📋 **Suggestion Details**\n\n"
                f"**From:** {suggestion['first_name']} (@{suggestion['username']}) = `{suggestion['user_id']}`\n"
                f"**Date:** `{suggestion['date']}` & `{suggestion['time']}` PHT\n\n"
                f"**Message:**\n{suggestion['message']}\n\n"
                f"**Status:** {suggestion['status']}"
            )
            
            # Create back button
            back_keyboard = InlineKeyboardMarkup([
                [InlineKeyboardButton("🔙 Back", callback_data=f"back_suggestion:{suggestion_id}")]
            ])
            
            await callback_query.edit_message_text(
                text=suggestion_msg,
                reply_markup=back_keyboard
            )
            
        elif data.startswith("feedback_suggestion:"):
            suggestion_id = data.split(":", 1)[1]
            
            if suggestion_id not in suggestion_data:
                await callback_query.answer("❌ Suggestion data not found!", show_alert=True)
                return
            
            suggestion = suggestion_data[suggestion_id]
            user_id = suggestion['user_id']
            
            # Update status to Pending with emoji
            suggestion_data[suggestion_id]['status'] = 'Pending ⏳'
            
            # Send feedback message to user
            feedback_msg = (
                "📬 **Suggestion Update**\n\n"
                "✅ Your suggestion has been read by our admin team!\n\n"
                "🔍 **Status:** Under Review\n"
                "📊 Your feedback is currently being analyzed by our development team. "
                "We carefully consider all suggestions to improve our services.\n\n"
                "🙏 Thank you for helping us make our bot better!\n\n"
                "💡 Feel free to send more suggestions anytime using `/suggest`"
            )
            
            try:
                await client.send_message(
                    chat_id=user_id,
                    text=feedback_msg
                )
                await callback_query.answer("✅ Feedback sent to user successfully! Status updated to Pending.", show_alert=True)
                logger.info(f"Feedback sent to user {user_id} for suggestion {suggestion_id}")
            except Exception as e:
                logger.error(f"Failed to send feedback to user {user_id}: {e}")
                await callback_query.answer("❌ Failed to send feedback to user!", show_alert=True)
                
        elif data.startswith("done_suggestion:"):
            suggestion_id = data.split(":", 1)[1]
            
            if suggestion_id not in suggestion_data:
                await callback_query.answer("❌ Suggestion data not found!", show_alert=True)
                return
            
            suggestion = suggestion_data[suggestion_id]
            user_id = suggestion['user_id']
            
            # Update status to Done with emoji
            suggestion_data[suggestion_id]['status'] = 'Done ✅'
            
            # Send completion message to user
            done_msg = (
                "🎉 **Suggestion Implemented!**\n\n"
                "✅ **Great news!** Your suggestion has been successfully added to the bot!\n\n"
                "🚀 **Status:** Completed\n"
                "💡 Your valuable feedback has been implemented and is now part of our bot's features. "
                "Thank you for helping us improve!\n\n"
                "🌟 We appreciate users like you who contribute to making our bot better. "
                "Your suggestion is now live and benefiting all users!\n\n"
                "💬 Keep the suggestions coming! Use `/suggest` anytime you have new ideas."
            )
            
            try:
                await client.send_message(
                    chat_id=user_id,
                    text=done_msg
                )
                await callback_query.answer("✅ Success notification sent to user! Status updated to Done.", show_alert=True)
                logger.info(f"Done notification sent to user {user_id} for suggestion {suggestion_id}")
            except Exception as e:
                logger.error(f"Failed to send done notification to user {user_id}: {e}")
                await callback_query.answer("❌ Failed to send notification to user!", show_alert=True)
                
        elif data.startswith("back_suggestion:"):
            suggestion_id = data.split(":", 1)[1]
            
            if suggestion_id not in suggestion_data:
                await callback_query.answer("❌ Suggestion data not found!", show_alert=True)
                return
            
            suggestion = suggestion_data[suggestion_id]
            current_status = suggestion['status']
            
            # Restore original notification message with current status
            notification_msg = (
                f"📬 **Suggestion Management**\n\n"
                f"💡 A user has submitted a suggestion for the bot.\n"
                f"📅 **Received:** {suggestion['date']}\n"
                f"📊 **Current Status:** {current_status}\n\n"
                "Click the buttons below to manage this suggestion:"
            )
            
            keyboard = InlineKeyboardMarkup([
                [
                    InlineKeyboardButton("📖 Read", callback_data=f"read_suggestion:{suggestion_id}"),
                    InlineKeyboardButton("💬 Feedback", callback_data=f"feedback_suggestion:{suggestion_id}")
                ],
                [
                    InlineKeyboardButton("Done ✅", callback_data=f"done_suggestion:{suggestion_id}")
                ]
            ])
            
            await callback_query.edit_message_text(
                text=notification_msg,
                reply_markup=keyboard
            )
            
    except Exception as e:
        logger.error(f"Error handling suggestion callback: {e}")
        await callback_query.answer("❌ An error occurred!", show_alert=True)

def setup_suggest_handler(app: Client):
    """Setup suggestion handlers"""
    
    # Command handler
    @app.on_message(filters.command("suggest") & filters.private)
    async def suggest_handler(client: Client, message: Message):
        await suggest_command(client, message)
    
    # Callback query handler
    @app.on_callback_query(filters.regex(r"^(read_suggestion|feedback_suggestion|done_suggestion|back_suggestion):"))
    async def callback_handler(client: Client, callback_query: CallbackQuery):
        await handle_suggestion_callbacks(client, callback_query)
    
    logger.info("Suggestions module handlers registered successfully")



const express = require("express");
const messageRoutes = new express.Router();
const Message = require("../models/message")

/** GET /:id - get detail of message.
 *
 * => {message: {id,
 *               body,
 *               sent_at,
 *               read_at,
 *               from_user: {username, first_name, last_name, phone},
 *               to_user: {username, first_name, last_name, phone}}
 *
 * Make sure that the currently-logged-in users is either the to or from user.
 *
 **/

 messageRoutes.get("/:id", ensureCorrectUser, async (req, res) => {
    const id = req.params.id
    const message = await Message.get(id)
    return res.json(message)
 })

/** POST / - post message.
 *
 * {to_username, body} =>
 *   {message: {id, from_username, to_username, body, sent_at}}
 *
 **/
 messageRoutes.post("/", ensureLoggedIn, async (req, res) => {
    const {to_username, body} = req.body
    const username = req.user
    const message = await Message.create({username, to_username, body})
    return res.json(message)
 })

/** POST/:id/read - mark message as read:
 *
 *  => {message: {id, read_at}}
 *
 * Make sure that the only the intended recipient can mark as read.
 *
 **/

 messageRoutes.post("/:id/read", ensureLoggedIn, async (req, res) => {
    const message = req.body
    const message = await Message.markRead(message.id)
    return res.json(message)
 })

module.exports = messageRoutes
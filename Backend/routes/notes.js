const express = require("express");
const router = express.Router();
var fetchuser = require('../middleware/fetchUser');
const Notes = require("../models/Notes");
const { body, validationResult } = require('express-validator');

//ROUTE 1:Get all the notes using:GET "/api/notes/fetchallnotes".login required
router.get('/fetchallnotes', fetchuser, async (req, res) => {
     try {
     const notes = await Notes.find({ user: req.user.id });
     res.json(notes);
} catch (error) {
     console.log(error.message);
     res.status(400).send("Internal server error");  
}
})

//ROUTE 2:Add a new note using:POST "/api/notes/addnote".login required
router.post('/addnote', fetchuser, [
     body('title', 'Enter a title').isLength({ min: 3 }),
     body('description', 'Description must be atleast 5 characters').isLength({ min: 5 }),
], async (req, res) => {
     try {
     
     const { title, description, tag } = req.body;
     //if there are errors,return bad request and the errors
     const errors = validationResult(req);
     if (!errors.isEmpty()) {
          return res.status(400).json({ errors: errors.array() });
     }
     const note = new Notes({
          title, description, tag, user: req.user.id
     })
     const savedNotes=await note.save()
     res.json(savedNotes);
          
} catch (error) {
     console.log(error.message);
     res.status(400).send("Internal server error");   
}
})
//ROUTE 3:Update an existing note using:PUT "/api/notes/updatenote".login required
router.put('/updatenote/:id', fetchuser, async (req, res) => {
     const{title,description,tag}=req.body;
     try {
     //create a new note
     const newNote={};
     if(title){newNote.title=title};
     if(description){newNote.description=description};
     if(tag){newNote.tag=tag};

     //find the note to be updated and update it
     let note=await Notes.findById(req.params.id);
     if(!note)
          {
              return res.status(404).send("Not Found")
          }
     if(note.user.toString()!==req.user.id){
          return res.status(401).send("Not Allowed")
     }
     note=await Notes.findByIdAndUpdate(req.params.id,{$set:newNote},{new:true});
     res.json({note})
}
     catch (error) {
          console.log(error.message);
          res.status(400).send("Internal server error");   
     }
})
//ROUTE 4:Delete an existing note using:DELETE "/api/notes/deletenote".login required
router.delete('/deletenote/:id', fetchuser, async (req, res) => {
    try{
     //find the note to be deleted and delete it
     let note=await Notes.findById(req.params.id);
     if(!note)
          {
              return res.status(404).send("Not Found")
          }
     //Allow deletion only if user owns this note
     if(note.user.toString()!==req.user.id){
          return res.status(401).send("Not Allowed")
     }
     note=await Notes.findByIdAndDelete(req.params.id);
     res.json({"sucess":"Note has been deleted",note:note})
}
catch (error) {
     console.log(error.message);
     res.status(400).send("Internal server error");   
}
})
module.exports = router